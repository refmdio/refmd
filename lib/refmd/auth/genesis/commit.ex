defmodule RefMD.Auth.Genesis.Commit do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.{ConsumedAccountGenesisReceipt, PendingAccountGenesis}
  alias RefMD.Auth.Genesis.{Authorization, Intent}
  alias RefMD.Auth.{PendingGenesisChallenge, PendingGenesisIntent, PendingGenesisSession}
  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Encryption
  alias RefMD.Encryption.{RotationPolicy, UserEncryptedIdentityKey, WorkspaceMemberEnvelope}
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Users.{User, UserSettings}
  alias RefMD.Workspaces.{Workspace, WorkspaceMember, WorkspaceRole}

  @receipt_protocol "refmd.audit.consumed-compound-intent-receipt"
  @response_content_type "application/json"

  def commit(genesis, session, authorization)
      when is_struct(genesis, PendingAccountGenesis) and
             is_struct(session, PendingGenesisSession) and is_map(authorization) do
    authorization_hash = hash(authorization)

    Repo.transaction(
      fn ->
        case replay_receipt(authorization, authorization_hash) do
          {:ok, response} -> %{response: response, session_token: nil, replay?: true}
          :not_found -> commit_new!(genesis, session, authorization, authorization_hash)
        end
      end,
      isolation: :serializable
    )
  rescue
    error in [ArgumentError, Ecto.InvalidChangesetError] -> {:error, error_message(error)}
  end

  def commit(_, _, _), do: {:error, :genesis_authorization_invalid}

  defp commit_new!(genesis, session, authorization, authorization_hash) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    {locked_genesis, locked_session, challenge, pending} = lock_pending!(genesis, session, now)

    verified = Authorization.verify!(locked_genesis, challenge, pending, authorization)
    intent = verified.intent
    prepare = verified.prepare
    prepared = verified.prepared
    materialized = materialize_authorization!(intent, authorization)

    insert_user!(locked_genesis, now)
    insert_account_records!(locked_genesis, challenge, prepare, prepared)
    insert_workspace!(locked_genesis, now)
    device = insert_device!(locked_genesis, challenge, intent, prepare, prepared, materialized)
    insert_initial_key_directories!(prepare, intent, materialized)
    insert_workspace_member_envelope!(prepare, prepared, intent, materialized)
    audit = insert_signed_audit_scopes!(prepare, intent, materialized)

    {:ok, auth_session, session_token} =
      RefMD.Auth.create_session(prepare["user_id"], %{
        device_id: prepare["device_id"],
        remember_me: false
      })

    response = %{
      "status" => "committed",
      "user_id" => prepare["user_id"],
      "device_id" => device.id,
      "workspace_id" => prepare["workspace_id"],
      "user_audit_checkpoint_hash" => audit.user.signed_checkpoint.checkpoint_hash,
      "workspace_audit_checkpoint_hash" => audit.workspace.signed_checkpoint.checkpoint_hash
    }

    consume_pending!(locked_genesis, locked_session, challenge, now)
    insert_receipt!(pending, authorization_hash, response, now)

    %{response: response, session: auth_session, session_token: session_token, replay?: false}
  end

  defp replay_receipt(authorization, authorization_hash) do
    compound_intent_id = authorization["compound_intent_id"]
    mutation_id = authorization["mutation_id"]

    if is_binary(compound_intent_id) and is_binary(mutation_id) do
      case Repo.get_by(ConsumedAccountGenesisReceipt,
             compound_intent_id: compound_intent_id,
             mutation_id: mutation_id
           ) do
        nil ->
          :not_found

        receipt ->
          replay_existing_receipt(receipt, authorization, authorization_hash)
      end
    else
      :not_found
    end
  end

  defp replay_existing_receipt(receipt, authorization, authorization_hash) do
    if receipt.intent_hash == authorization["intent_hash"] and
         receipt.authorization_hash == authorization_hash do
      {:ok, decode_canonical!(receipt.response_body_jcs_b64u)}
    else
      Repo.rollback(:audit_checkpoint_intent_reuse)
    end
  end

  defp lock_pending!(genesis, session, now) do
    locked_genesis = lock_one!(PendingAccountGenesis, genesis.registration_id)
    locked_session = lock_one!(PendingGenesisSession, genesis.registration_id)
    challenge = lock_one!(PendingGenesisChallenge, genesis.registration_id)
    pending = lock_one!(PendingGenesisIntent, genesis.registration_id)

    valid? =
      locked_session.token_hash == session.token_hash and
        challenge.pending_genesis_session_token_hash == locked_session.token_hash and
        Enum.all?([locked_genesis, locked_session, challenge, pending], fn row ->
          is_nil(Map.get(row, :consumed_at)) and DateTime.compare(row.expires_at, now) == :gt
        end)

    unless valid?, do: Repo.rollback(:invalid_genesis_session)
    {locked_genesis, locked_session, challenge, pending}
  end

  defp lock_one!(schema, id) do
    from(row in schema, where: row.registration_id == ^id, lock: "FOR UPDATE")
    |> Repo.one()
    |> case do
      nil -> Repo.rollback(:invalid_genesis_session)
      row -> row
    end
  end

  defp insert_user!(genesis, now) do
    %User{id: genesis.reserved_user_id, encryption_setup_at: now}
    |> User.changeset(%{
      email: genesis.normalized_email,
      name: genesis.display_name,
      account_type: "registered"
    })
    |> Repo.insert!()

    %UserSettings{user_id: genesis.reserved_user_id, updated_at: now}
    |> Repo.insert!()
  end

  defp insert_account_records!(genesis, challenge, prepare, prepared) do
    credential = genesis.credential
    recovery = prepared.recovery_authorization
    secret = prepared.secret_record

    insert!(
      Encryption.create_user_encrypted_master_key(%{
        user_id: prepare["user_id"],
        auth_type: "password",
        encrypted_umk: decode!(prepare["encrypted_umk"]),
        umk_nonce: decode!(prepare["encrypted_umk_nonce"]),
        salt: decode!(credential["salt_b64u"]),
        kdf_type: credential["kdf_type"],
        kdf_params: runtime_kdf_params!(credential),
        auth_key_hash: credential["auth_key_verifier"],
        recovery_encrypted_umk: decode!(recovery["recovery_encrypted_umk"]),
        recovery_nonce: decode!(recovery["recovery_nonce"]),
        recovery_authorization_public_material:
          recovery["recovery_authorization_public_material"],
        recovery_authorization_key_id: recovery["recovery_authorization_key_id"]
      })
    )

    insert!(
      Encryption.create_user_identity_public_key(%{
        user_id: prepare["user_id"],
        key_version: 1,
        lifecycle_state: "current",
        rotation_due_at: RotationPolicy.next_identity_due_at(),
        hybrid_encryption_public_key_material:
          prepare["identity_hybrid_encryption_public_key_material"],
        hybrid_signing_public_key_material:
          prepare["identity_hybrid_signing_public_key_material"],
        pending_registration_challenge_hash: challenge.challenge_hash
      })
    )

    encrypted_attrs = %{
      user_id: secret["user_id"],
      id: secret["id"],
      identity_key_epoch: secret["identity_key_epoch"],
      previous_record_hash: secret["previous_record_hash"],
      encrypted_identity_hybrid_encryption_private_key_material:
        decode!(secret["encrypted_identity_hybrid_encryption_private_key_material"]),
      identity_hybrid_encryption_private_key_material_nonce:
        decode!(secret["identity_hybrid_encryption_private_key_material_nonce"]),
      encryption_key_id: secret["encryption_key_id"],
      encrypted_identity_hybrid_signing_private_key_material:
        decode!(secret["encrypted_identity_hybrid_signing_private_key_material"]),
      identity_hybrid_signing_private_key_material_nonce:
        decode!(secret["identity_hybrid_signing_private_key_material_nonce"]),
      signing_key_id: secret["signing_key_id"],
      signing_material_aad_hash: secret["signing_material_aad_hash"],
      encryption_material_aad_hash: secret["encryption_material_aad_hash"],
      record_hash: secret["record_hash"],
      is_current: true
    }

    %UserEncryptedIdentityKey{}
    |> UserEncryptedIdentityKey.changeset(encrypted_attrs)
    |> Repo.insert!()
  end

  defp runtime_kdf_params!(%{
         "kdf_type" => "argon2id",
         "kdf_params" => %{
           "memory_kib" => memory,
           "iterations" => iterations,
           "parallelism" => parallelism
         }
       }) do
    %{
      "algorithm" => "argon2id",
      "memory" => memory,
      "iterations" => iterations,
      "parallelism" => parallelism,
      "hash_length" => 32
    }
  end

  defp insert_workspace!(genesis, now) do
    workspace_id = genesis.reserved_workspace_id

    %Workspace{
      id: workspace_id,
      current_kek_version: 1,
      min_kek_version: 1,
      kek_rotation_due_at: RotationPolicy.next_kek_due_at()
    }
    |> Workspace.changeset(%{
      name: "#{genesis.display_name}'s Workspace",
      slug: "workspace-#{String.slice(workspace_id, 0, 8)}",
      owner_id: genesis.reserved_user_id
    })
    |> Repo.insert!()

    roles = [
      {"owner", "Owner"},
      {"admin", "Admin"},
      {"editor", "Editor"},
      {"viewer", "Viewer"}
    ]

    Enum.each(roles, fn {base_role, name} ->
      %WorkspaceRole{id: genesis.reserved_workspace_role_ids[base_role], created_at: now}
      |> WorkspaceRole.changeset(%{
        workspace_id: workspace_id,
        name: name,
        base_role: base_role,
        is_default: base_role == "editor"
      })
      |> Repo.insert!()
    end)

    %WorkspaceMember{joined_at: now}
    |> WorkspaceMember.changeset(%{
      workspace_id: workspace_id,
      user_id: genesis.reserved_user_id,
      role_id: genesis.reserved_workspace_role_ids["owner"],
      is_default: true,
      joined_at: now
    })
    |> Repo.insert!()
  end

  defp insert_device!(genesis, challenge, intent, prepare, prepared, materialized) do
    transcript = genesis_transcript!(genesis, challenge, intent, prepare, prepared)
    user_checkpoint = materialized.user.checkpoint["payload"]
    user_checkpoint_hash = Encryption.KeyDirectory.checkpoint_hash(user_checkpoint)
    signature = materialized.genesis_authorization["signature"]
    details = genesis_proof_details(genesis, challenge, intent, prepare, prepared)

    proof =
      Signature.build_device_approval_proof!(
        "genesis_device_bootstrap",
        transcript,
        details,
        %{
          "approving_signing_key_id" => prepared.identity_signing_key_id,
          "approving_key_checkpoint_sequence" => 1,
          "approving_key_checkpoint_hash" => user_checkpoint_hash,
          "target_device_id" => prepare["device_id"],
          "target_device_signing_key_id" => prepared.device_signing_key_id,
          "target_device_hybrid_signing_public_key_material_hash" =>
            hash(prepare["device_hybrid_signing_public_key_material"]),
          "target_device_hybrid_encryption_public_key_material_hash" =>
            hash(prepare["device_hybrid_encryption_public_key_material"]),
          "target_device_encryption_key_id" => prepared.device_encryption_key_id,
          "target_device_client_nonce_hash" => hash_bytes(decode!(prepare["client_nonce"])),
          "target_key_checkpoint_sequence" => 1,
          "target_key_checkpoint_hash" => user_checkpoint_hash
        }
      )

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    %Device{last_seen_at: now, created_at: now}
    |> Device.changeset(%{
      id: prepare["device_id"],
      user_id: prepare["user_id"],
      name: prepare["name"],
      device_type: prepare["device_type"],
      hybrid_encryption_public_key_material:
        prepare["device_hybrid_encryption_public_key_material"],
      hybrid_signing_public_key_material: prepare["device_hybrid_signing_public_key_material"],
      approval_signature: signature,
      approval_signature_surface: "genesis_device_bootstrap",
      approval_proof: proof,
      client_nonce: decode!(prepare["client_nonce"]),
      last_seen_at: now
    })
    |> Repo.insert!()
  end

  defp insert_initial_key_directories!(prepare, intent, materialized) do
    insert_initial_key_directory!("user", fn ->
      Encryption.insert_initial_user_key_directory!(
        prepare["user_id"],
        materialized.user.events,
        materialized.user.checkpoint,
        checkpoint_signer_kind: "identity"
      )
    end)

    insert_initial_key_directory!("workspace", fn ->
      Encryption.insert_initial_workspace_key_directory!(
        prepare["workspace_id"],
        materialized.workspace.events,
        materialized.workspace.checkpoint,
        checkpoint_signer_kind: "device"
      )
    end)

    [user_scope, workspace_scope] = intent["scopes"]
    assert_scope_hash!(user_scope, materialized.user.checkpoint)
    assert_scope_hash!(workspace_scope, materialized.workspace.checkpoint)
  end

  defp insert_initial_key_directory!(scope_kind, insert) do
    insert.()
  rescue
    error in ArgumentError ->
      reraise ArgumentError,
              [message: "genesis_#{scope_kind}_key_directory_#{error.message}"],
              __STACKTRACE__
  end

  defp insert_workspace_member_envelope!(prepare, prepared, intent, materialized) do
    [_user_scope, workspace_scope] = intent["scopes"]
    envelope_effect = find_effect!(workspace_scope, "workspace_member_envelope_issued")
    event_payload = envelope_effect["event_payload"]
    event_hash = envelope_effect["event_hash"]
    checkpoint = workspace_scope["candidate_key_directory_checkpoint_payload"]
    covered_head = checkpoint["covered_event_head"]
    precommit = prepare["workspace_member_envelope_precommit"]
    wrap = precommit["wrap"]
    signature = materialized.pq_authorization["signature"]

    envelope =
      wrap
      |> Map.put("event", %{
        "wrap_event_sequence" => event_payload["sequence"],
        "wrap_event_hash" => event_hash,
        "wrap_event_body_hash" => hash(event_payload["body"])
      })
      |> Map.put("operation_checkpoint", %{
        "checkpoint_sequence" => checkpoint["sequence"],
        "checkpoint_hash" => workspace_scope["candidate_key_directory_checkpoint_hash"],
        "covered_event_head_sequence" => covered_head["head_sequence"],
        "covered_event_head_hash" => covered_head["head_hash"]
      })
      |> Map.put("transcript_hash", signature["transcript_hash"])
      |> Map.put("signature", signature)
      |> Map.merge(%{
        "target_user_id" => prepare["user_id"],
        "sender_device_id" => prepare["device_id"],
        "key_version" => 1
      })

    attrs =
      envelope
      |> SignedPQ.attrs_from_container_params!()
      |> Map.merge(%{
        workspace_id: prepare["workspace_id"],
        target_user_id: prepare["user_id"],
        sender_device_id: prepare["device_id"],
        key_version: 1
      })

    unless prepared.member_envelope.commitment_hash ==
             event_payload["body"]["workspace_member_envelope_hash"],
           do: Repo.rollback(:genesis_member_envelope_mismatch)

    %WorkspaceMemberEnvelope{created_at: DateTime.utc_now()}
    |> WorkspaceMemberEnvelope.changeset(attrs)
    |> Repo.insert!()
  end

  defp insert_signed_audit_scopes!(prepare, intent, materialized) do
    [user_scope, workspace_scope] = intent["scopes"]

    user =
      insert_signed_audit_scope!(user_scope, materialized.user_audit_signature,
        chain_scope_kind: "user",
        chain_scope_id: prepare["user_id"],
        signer_user_id: prepare["user_id"],
        signer_device_id: nil,
        public_key_material: prepare["identity_hybrid_signing_public_key_material"]
      )

    workspace =
      insert_signed_audit_scope!(workspace_scope, materialized.workspace_audit_signature,
        chain_scope_kind: "workspace",
        chain_scope_id: prepare["workspace_id"],
        signer_user_id: prepare["user_id"],
        signer_device_id: prepare["device_id"],
        public_key_material: prepare["device_hybrid_signing_public_key_material"]
      )

    %{user: user, workspace: workspace}
  end

  defp insert_signed_audit_scope!(scope, scope_signature, authority) do
    events = Enum.map(scope["candidate_events"], &audit_attrs/1)
    checkpoint_payload = audit_checkpoint_payload(scope, scope_signature)

    checkpoint = %{
      "payload" => checkpoint_payload,
      "signature" => scope_signature["signature"],
      "checkpoint_hash" => scope_signature["checkpoint_hash"]
    }

    case Security.record_signed_audit_events(events, checkpoint, [],
           genesis_candidate_authority: Map.new(authority)
         ) do
      {:ok, result} -> result
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp audit_attrs(event) do
    actor = event["event_body"]["actor"]

    workspace_id =
      if event["chain_scope_kind"] == "workspace", do: event["chain_scope_id"], else: nil

    %{
      event_id: event["event_id"],
      class: "authority",
      type: event["event_type"],
      actor: %{
        "user_id" => actor["user_id"],
        "device_id" => actor["device_id"],
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => actor["user_id"]
      },
      scope: %{"workspace_id" => workspace_id, "document_id" => nil, "share_id" => nil},
      resource: %{
        "kind" => if(workspace_id, do: "workspace", else: "credential"),
        "id" => event["event_body"]["subject_id"],
        "version_hash" => nil
      },
      action: %{"operation" => event["event_type"], "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      },
      event_body: event["event_body"]
    }
  end

  defp signer_user_id(%{"chain_scope_kind" => "user", "chain_scope_id" => user_id}), do: user_id

  defp signer_user_id(scope),
    do: scope["candidate_events"] |> List.last() |> get_in(["event_body", "actor", "user_id"])

  defp signer_device_id(%{"chain_scope_kind" => "user"}), do: nil

  defp signer_device_id(scope),
    do: scope["candidate_events"] |> List.last() |> get_in(["event_body", "actor", "device_id"])

  defp materialize_authorization!(intent, authorization) do
    [user_scope, workspace_scope] = intent["scopes"]
    entries = authorization["effect_authorizations"]
    {user, entries} = materialize_scope!(user_scope, entries)
    {workspace, []} = materialize_scope!(workspace_scope, entries)

    %{
      user: user,
      workspace: workspace,
      user_audit_signature: Enum.at(authorization["scope_signatures"], 0),
      workspace_audit_signature: Enum.at(authorization["scope_signatures"], 1),
      pq_authorization: find_authorization!(authorization, "pq_wrap"),
      genesis_authorization: find_authorization!(authorization, "genesis_device_bootstrap")
    }
  end

  defp materialize_scope!(scope, entries) do
    requirements = scope["effect_signature_requirements"]
    {scope_entries, rest} = Enum.split(entries, length(requirements))

    envelopes =
      Enum.zip(requirements, scope_entries)
      |> Enum.map(fn {requirement, entry} ->
        unless requirement["authorization_kind"] == entry["authorization_kind"] and
                 requirement["requirement_order"] == entry["requirement_order"],
               do: raise(ArgumentError, "genesis_authorization_order_invalid")

        {requirement, entry}
      end)

    events =
      envelopes
      |> Enum.filter(fn {requirement, _} ->
        requirement["authorization_kind"] == "key_directory_event"
      end)
      |> Enum.map(fn {requirement, entry} ->
        effect =
          Enum.at(scope["candidate_key_directory_effects"], requirement["requirement_order"] - 1)

        payload = effect["event_payload"]

        %{
          "payload" => payload,
          "signatures" => [%{"signer" => payload["actor"], "signature" => entry["signature"]}]
        }
      end)

    {checkpoint_requirement, checkpoint_entry} =
      Enum.find(envelopes, fn {requirement, _} ->
        requirement["authorization_kind"] == "key_directory_checkpoint"
      end) || raise(ArgumentError, "genesis_checkpoint_authorization_missing")

    checkpoint = %{
      "payload" => scope["candidate_key_directory_checkpoint_payload"],
      "signatures" => [
        %{
          "signer" => checkpoint_signer(scope, checkpoint_requirement),
          "signature" => checkpoint_entry["signature"]
        }
      ]
    }

    {%{events: events, checkpoint: checkpoint}, rest}
  end

  defp checkpoint_signer(%{"chain_scope_kind" => "user"} = scope, requirement) do
    %{
      "signer_kind" => "identity",
      "user_id" => scope["chain_scope_id"],
      "signing_key_id" => requirement["signer_key_id"],
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }
  end

  defp checkpoint_signer(scope, requirement) do
    actor = scope["candidate_key_directory_effects"] |> hd() |> get_in(["event_payload", "actor"])

    %{
      "signer_kind" => "device",
      "user_id" => actor["user_id"],
      "device_id" => actor["device_id"],
      "signing_key_id" => requirement["signer_key_id"],
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }
  end

  defp genesis_transcript!(genesis, challenge, intent, prepare, prepared) do
    details = genesis_proof_details(genesis, challenge, intent, prepare, prepared)

    Signature.build_genesis_device_bootstrap_transcript!(%{
      registration_id: details["registration_id"],
      compound_intent_id: details["compound_intent_id"],
      mutation_id: details["mutation_id"],
      genesis_compound_context_hash: details["genesis_compound_context_hash"],
      user_id: prepare["user_id"],
      workspace_id: details["workspace_id"],
      owner_role_id: details["owner_role_id"],
      device_id: prepare["device_id"],
      device_public_material: prepare["device_hybrid_signing_public_key_material"],
      device_hybrid_encryption_public_key_material:
        prepare["device_hybrid_encryption_public_key_material"],
      client_nonce: prepare["client_nonce"],
      registration_challenge_hash: details["registration_challenge_hash"],
      identity_signing_key_id: prepared.identity_signing_key_id,
      user_identity_public_key_hash: details["user_identity_public_key_hash"],
      user_device_key_added_event_hash: details["user_device_key_added_event_hash"],
      workspace_device_key_added_event_hash: details["workspace_device_key_added_event_hash"],
      owner_member_added_event_hash: details["owner_member_added_event_hash"],
      workspace_member_envelope_commitment_hash:
        details["workspace_member_envelope_commitment_hash"],
      user_audit_checkpoint: details["user_audit_checkpoint"],
      workspace_audit_checkpoint: details["workspace_audit_checkpoint"]
    })
  end

  defp genesis_proof_details(genesis, challenge, intent, prepare, prepared) do
    [user_scope, workspace_scope] = intent["scopes"]
    user_device = find_effect!(user_scope, "device_key_added")
    workspace_device = find_effect!(workspace_scope, "device_key_added")
    owner_member = find_effect!(workspace_scope, "member_added")

    links = %{
      user_device_key_added_event_hash: user_device["event_hash"],
      workspace_device_key_added_event_hash: workspace_device["event_hash"],
      owner_user_id: prepare["user_id"],
      owner_role_id: prepare["owner_role_id"],
      owner_member_added_event_hash: owner_member["event_hash"],
      workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash
    }

    %{
      "kind" => "genesis_device_bootstrap",
      "registration_id" => genesis.registration_id,
      "compound_intent_id" => intent["compound_intent_id"],
      "mutation_id" => intent["mutation_id"],
      "genesis_compound_context_hash" =>
        Intent.compound_context_hash!(
          genesis.registration_id,
          prepared.prepare_request_hash,
          intent,
          links
        ),
      "workspace_id" => prepare["workspace_id"],
      "owner_role_id" => prepare["owner_role_id"],
      "registration_challenge_hash" => challenge.challenge_hash,
      "user_identity_public_key_hash" =>
        hash(prepare["identity_hybrid_signing_public_key_material"]),
      "user_device_key_added_event_hash" => user_device["event_hash"],
      "workspace_device_key_added_event_hash" => workspace_device["event_hash"],
      "owner_member_added_event_hash" => owner_member["event_hash"],
      "workspace_member_envelope_commitment_hash" => prepared.member_envelope.commitment_hash,
      "user_audit_checkpoint" => %{
        "sequence" => 2,
        "checkpoint_hash" => user_scope["checkpoint_payload_hash"]
      },
      "workspace_audit_checkpoint" => %{
        "sequence" => 1,
        "checkpoint_hash" => workspace_scope["checkpoint_payload_hash"]
      }
    }
  end

  defp find_effect!(scope, event_type) do
    Enum.find(scope["candidate_key_directory_effects"], fn effect ->
      effect["event_payload"]["event_type"] == event_type
    end) || raise(ArgumentError, "genesis_effect_missing")
  end

  defp find_authorization!(authorization, kind) do
    Enum.find(authorization["effect_authorizations"], &(&1["authorization_kind"] == kind)) ||
      raise(ArgumentError, "genesis_effect_authorization_missing")
  end

  defp assert_scope_hash!(scope, checkpoint) do
    unless Encryption.KeyDirectory.checkpoint_hash(checkpoint["payload"]) ==
             scope["candidate_key_directory_checkpoint_hash"],
           do: Repo.rollback(:genesis_checkpoint_hash_mismatch)
  end

  defp insert_receipt!(pending, authorization_hash, response, now) do
    response_bytes = JCS.canonical_bytes!(response)

    %ConsumedAccountGenesisReceipt{}
    |> ConsumedAccountGenesisReceipt.changeset(%{
      registration_id: pending.registration_id,
      protocol: @receipt_protocol,
      version: 1,
      compound_intent_id: pending.compound_intent_id,
      mutation_id: pending.mutation_id,
      intent_hash: pending.intent_hash,
      authorization_hash: authorization_hash,
      response_status: 201,
      response_content_type: @response_content_type,
      response_body_jcs_b64u: Base.url_encode64(response_bytes, padding: false),
      response_hash: Hash.blake3_base64url(response_bytes),
      committed_at: now
    })
    |> Repo.insert!()
  end

  defp consume_pending!(genesis, session, challenge, now) do
    genesis |> Ecto.Changeset.change(consumed_at: now) |> Repo.update!()
    session |> Ecto.Changeset.change(consumed_at: now) |> Repo.update!()
    challenge |> Ecto.Changeset.change(consumed_at: now) |> Repo.update!()
  end

  defp audit_checkpoint_payload(scope, signature) do
    event = List.last(scope["candidate_events"])
    signer_user_id = signer_user_id(scope)

    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => scope["chain_scope_kind"],
      "chain_scope_id" => scope["chain_scope_id"],
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "signer_user_id" => signer_user_id,
      "signing_key_id" => signature["signature"]["signing_key_id"],
      "authorization_checkpoint_scope_kind" => scope["chain_scope_kind"],
      "authorization_checkpoint_scope_id" => scope["chain_scope_id"],
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => event["event_type"]
    }
    |> maybe_put("signer_device_id", signer_device_id(scope))
  end

  defp insert!({:ok, value}), do: value
  defp insert!({:error, reason}), do: Repo.rollback(reason)

  defp decode!(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, decoded} -> decoded
      :error -> raise ArgumentError, "invalid_base64_encoding"
    end
  end

  defp decode_canonical!(value) do
    value
    |> decode!()
    |> Jason.decode!()
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp hash_bytes(value), do: Hash.blake3_base64url(value)

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp error_message(%ArgumentError{message: message}), do: message
  defp error_message(%Ecto.InvalidChangesetError{changeset: changeset}), do: changeset
end
