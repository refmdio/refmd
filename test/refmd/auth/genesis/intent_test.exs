defmodule RefMD.Auth.Genesis.IntentTest do
  use RefMD.DataCase, async: false

  import Ecto.Query
  import RefMD.TestCrypto

  alias RefMD.Auth.ConsumedAccountGenesisReceipt
  alias RefMD.Auth.Genesis
  alias RefMD.Auth.Genesis.{Commit, Intent, Prepare}
  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature, Suite}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Repo
  alias RefMD.Security.CompoundAppend

  test "issues one exact account genesis compound intent and rejects changed prepare reuse" do
    user_id = Ecto.UUID.generate()

    {:ok, %{genesis: genesis, token: token}} =
      Genesis.begin_password_registration(%{
        "protocol" => "refmd.password-account-registration",
        "version" => 1,
        "reserved_user_id" => user_id,
        "email" => "genesis-intent@example.com",
        "display_name" => "Genesis Intent",
        "auth_key_b64u" => b64(:binary.copy(<<1>>, 32)),
        "salt_b64u" => b64(:binary.copy(<<2>>, 16)),
        "kdf_type" => "argon2id",
        "kdf_params" => %{
          "memory_kib" => 65_536,
          "iterations" => 3,
          "parallelism" => 4
        }
      })

    {:ok, ^genesis, session} = Genesis.get_pending_by_token(token)
    {:ok, challenge} = Genesis.issue_challenge(genesis, session)
    prepare = prepare_request(genesis, challenge.challenge)

    assert {:ok, intent} = Intent.issue!(genesis, session, prepare)
    assert ^intent = CompoundAppend.validate_intent!(intent)
    assert intent["protocol"] == "refmd.audit.compound-append-intent"
    assert intent["version"] == 1
    assert Enum.map(intent["scopes"], & &1["chain_scope_kind"]) == ["user", "workspace"]

    [user_scope, workspace_scope] = intent["scopes"]

    assert Enum.map(user_scope["candidate_events"], & &1["event_type"]) == [
             "user.account.genesis",
             "user.device.genesis_bootstrapped"
           ]

    assert Enum.map(workspace_scope["candidate_events"], & &1["event_type"]) == [
             "workspace.genesis"
           ]

    assert length(user_scope["candidate_key_directory_effects"]) == 4
    assert length(workspace_scope["candidate_key_directory_effects"]) == 6

    assert List.last(workspace_scope["effect_signature_requirements"])["authorization_kind"] ==
             "genesis_device_bootstrap"

    assert {:ok, ^intent} = Intent.issue!(genesis, session, prepare)

    assert {:error, :genesis_intent_reuse} =
             Intent.issue!(genesis, session, Map.put(prepare, "name", "Changed Device"))
  end

  test "commits the complete account genesis atomically and records an exact receipt" do
    user_id = Ecto.UUID.generate()

    {:ok, %{genesis: genesis, token: token}} =
      Genesis.begin_password_registration(%{
        "protocol" => "refmd.password-account-registration",
        "version" => 1,
        "reserved_user_id" => user_id,
        "email" => "genesis-commit@example.com",
        "display_name" => "Genesis Commit",
        "auth_key_b64u" => b64(:binary.copy(<<21>>, 32)),
        "salt_b64u" => b64(:binary.copy(<<22>>, 16)),
        "kdf_type" => "argon2id",
        "kdf_params" => %{
          "memory_kib" => 65_536,
          "iterations" => 3,
          "parallelism" => 4
        }
      })

    {:ok, ^genesis, session} = Genesis.get_pending_by_token(token)
    {:ok, challenge} = Genesis.issue_challenge(genesis, session)
    prepare = prepare_request(genesis, challenge.challenge)
    {:ok, intent} = Intent.issue!(genesis, session, prepare)
    authorization = compound_authorization(genesis, challenge, intent, prepare)
    assert ^authorization = CompoundAppend.validate_authorization!(authorization, intent)

    tampered_intent =
      put_in(intent, ["scopes", Access.at(0), "candidate_event_head", "sequence"], 99)

    assert_raise ArgumentError, "compound_intent_binding_invalid", fn ->
      CompoundAppend.validate_intent!(tampered_intent)
    end

    Enum.each(intent["scopes"], fn scope ->
      checkpoint = scope["candidate_key_directory_checkpoint_payload"]

      signing_ids =
        (checkpoint["identity_keys"] ++ checkpoint["device_keys"])
        |> Enum.filter(
          &(get_in(&1, ["key_material", "protocol"]) == "refmd.hybrid-signing-key-material")
        )
        |> Enum.map(& &1["key_id"])

      Enum.each(scope["candidate_key_directory_effects"], fn effect ->
        assert effect["event_payload"]["actor"]["signing_key_id"] in signing_ids
      end)
    end)

    assert {:ok, %{response: response, session_token: session_token, replay?: false}} =
             Commit.commit(genesis, session, authorization)

    assert is_binary(session_token)
    assert response["status"] == "committed"
    assert response["user_id"] == user_id
    assert response["device_id"] == prepare["device_id"]
    assert response["workspace_id"] == genesis.reserved_workspace_id
    assert Repo.get(RefMD.Users.User, user_id)
    assert Repo.get(RefMD.Devices.Device, prepare["device_id"])
    assert Repo.get(RefMD.Workspaces.Workspace, genesis.reserved_workspace_id)

    assert RefMD.Encryption.get_user_encrypted_master_key(user_id).kdf_params == %{
             "algorithm" => "argon2id",
             "memory" => 65_536,
             "iterations" => 3,
             "parallelism" => 4,
             "hash_length" => 32
           }

    assert RefMD.Encryption.current_user_key_directory_pin(user_id).checkpoint_sequence == 1

    assert RefMD.Encryption.current_workspace_key_directory_pin(genesis.reserved_workspace_id).checkpoint_sequence ==
             1

    assert %{signed_checkpoint: user_checkpoint} =
             RefMD.Security.current_signed_audit_checkpoint("user", user_id)

    assert user_checkpoint["checkpoint_hash"] == response["user_audit_checkpoint_hash"]

    assert %ConsumedAccountGenesisReceipt{} =
             Repo.get(ConsumedAccountGenesisReceipt, genesis.registration_id)

    audit_event_count = Repo.aggregate(RefMD.Security.AuditEvent, :count)

    assert {:ok, %{response: ^response, session_token: nil, replay?: true}} =
             Commit.commit(genesis, session, authorization)

    assert Repo.aggregate(RefMD.Security.AuditEvent, :count) == audit_event_count

    changed_authorization =
      put_in(
        authorization,
        ["scope_signatures", Access.at(0), "checkpoint_hash"],
        b64(:binary.copy(<<99>>, 32))
      )

    assert {:error, :audit_checkpoint_intent_reuse} =
             Commit.commit(genesis, session, changed_authorization)

    assert Repo.aggregate(RefMD.Security.AuditEvent, :count) == audit_event_count
  end

  test "rolls back every authoritative surface when compound authorization is tampered" do
    user_id = Ecto.UUID.generate()

    {:ok, %{genesis: genesis, token: token}} =
      Genesis.begin_password_registration(%{
        "protocol" => "refmd.password-account-registration",
        "version" => 1,
        "reserved_user_id" => user_id,
        "email" => "genesis-rollback@example.com",
        "display_name" => "Genesis Rollback",
        "auth_key_b64u" => b64(:binary.copy(<<31>>, 32)),
        "salt_b64u" => b64(:binary.copy(<<32>>, 16)),
        "kdf_type" => "argon2id",
        "kdf_params" => %{
          "memory_kib" => 65_536,
          "iterations" => 3,
          "parallelism" => 4
        }
      })

    {:ok, ^genesis, session} = Genesis.get_pending_by_token(token)
    {:ok, challenge} = Genesis.issue_challenge(genesis, session)
    prepare = prepare_request(genesis, challenge.challenge)
    {:ok, intent} = Intent.issue!(genesis, session, prepare)
    authorization = compound_authorization(genesis, challenge, intent, prepare)

    tampered =
      put_in(
        authorization,
        ["effect_authorizations", Access.at(0), "signature", "ed25519"],
        b64(:binary.copy(<<0>>, 64))
      )

    assert {:error, _reason} = Commit.commit(genesis, session, tampered)
    refute Repo.get(RefMD.Users.User, user_id)
    refute Repo.get(RefMD.Devices.Device, prepare["device_id"])
    refute Repo.get(RefMD.Workspaces.Workspace, genesis.reserved_workspace_id)
    refute Repo.get(ConsumedAccountGenesisReceipt, genesis.registration_id)
    assert RefMD.Encryption.current_user_key_directory_pin(user_id) == nil

    assert RefMD.Encryption.current_workspace_key_directory_pin(genesis.reserved_workspace_id) ==
             nil

    assert Repo.aggregate(
             from(event in RefMD.Security.AuditEvent,
               where:
                 event.chain_scope in [
                   ^"user:#{user_id}",
                   ^"workspace:#{genesis.reserved_workspace_id}"
                 ]
             ),
             :count
           ) == 0
  end

  defp compound_authorization(genesis, challenge, intent, prepare) do
    identity_private = hybrid_signing_private_key_material("identity", prepare["user_id"])
    device_private = hybrid_signing_private_key_material("device", prepare["device_id"])
    identity_public = hybrid_signing_public_key_material(identity_private)
    device_public = hybrid_signing_public_key_material(device_private)
    prepared = Prepare.validate!(genesis, prepare)

    scope_signatures =
      Enum.map(intent["scopes"], fn scope ->
        variant = scope["required_checkpoint_variant"]
        payload = audit_checkpoint_payload(scope, prepare)

        {owner_kind, owner_id, private, public} =
          if variant == "user_identity",
            do: {"identity", prepare["user_id"], identity_private, identity_public},
            else: {"device", prepare["device_id"], device_private, device_public}

        transcript =
          Audit.build_audit_checkpoint_transcript!(variant, owner_kind, owner_id, payload)

        %{
          "chain_scope_kind" => scope["chain_scope_kind"],
          "chain_scope_id" => scope["chain_scope_id"],
          "checkpoint_hash" => scope["checkpoint_payload_hash"],
          "checkpoint_variant" => variant,
          "signature" => sign("audit_checkpoint", transcript, private, public)
        }
      end)

    effect_authorizations =
      intent["scopes"]
      |> Enum.flat_map(fn scope ->
        Enum.map(scope["effect_signature_requirements"], fn requirement ->
          {transcript, private, public} =
            effect_signing_input(
              %{
                genesis: genesis,
                challenge: challenge,
                intent: intent,
                prepare: prepare,
                prepared: prepared,
                scope: scope,
                requirement: requirement
              },
              %{
                identity: {identity_private, identity_public},
                device: {device_private, device_public}
              }
            )

          %{
            "requirement_order" => requirement["requirement_order"],
            "authorization_kind" => requirement["authorization_kind"],
            "signing_purpose" => requirement["signing_purpose"],
            "surface_variant" => requirement["surface_variant"],
            "subject_hash" => requirement["subject_hash"],
            "signer_key_id" => requirement["signer_key_id"],
            "signature" => sign(requirement["signing_purpose"], transcript, private, public),
            "approval_proof" => "NONE"
          }
        end)
      end)

    %{
      "protocol" => "refmd.audit.compound-append-authorization",
      "version" => 1,
      "compound_intent_id" => intent["compound_intent_id"],
      "mutation_id" => intent["mutation_id"],
      "intent_hash" => hash(intent),
      "scope_signatures" => scope_signatures,
      "effect_authorizations" => effect_authorizations
    }
  end

  defp effect_signing_input(context, signing_materials) do
    %{
      genesis: genesis,
      challenge: challenge,
      intent: intent,
      prepare: prepare,
      prepared: prepared,
      scope: scope,
      requirement: requirement
    } = context

    %{identity: {identity_private, identity_public}, device: {device_private, device_public}} =
      signing_materials

    {owner_kind, owner_id, private, public} =
      if scope["chain_scope_kind"] == "user",
        do: {"identity", prepare["user_id"], identity_private, identity_public},
        else: {"device", prepare["device_id"], device_private, device_public}

    case requirement["authorization_kind"] do
      "key_directory_event" ->
        effect =
          Enum.at(scope["candidate_key_directory_effects"], requirement["requirement_order"] - 1)

        payload = effect["event_payload"]

        {Signature.build_key_directory_event_transcript!(
           payload["event_type"],
           owner_kind,
           owner_id,
           payload
         ), private, public}

      "key_directory_checkpoint" ->
        signer = checkpoint_signer(scope, requirement, prepare)

        {Signature.build_key_directory_checkpoint_transcript!(
           requirement["surface_variant"],
           owner_kind,
           owner_id,
           scope["candidate_key_directory_checkpoint_payload"],
           signer
         ), private, public}

      "pq_wrap" ->
        event = find_effect(scope, "workspace_member_envelope_issued")["event_payload"]
        member = prepared.member_envelope
        wrap = prepare["workspace_member_envelope_precommit"]["wrap"]
        event_hash = KeyDirectory.event_hash(event)

        {Signature.build_pq_wrap_transcript!(
           prepare["device_id"],
           wrap["sender"],
           %{
             "scope_kind" => "workspace",
             "scope_id" => prepare["workspace_id"],
             "event_hash" => event_hash,
             "operation_checkpoint_sequence" => 1,
             "operation_checkpoint_hash" => scope["candidate_key_directory_checkpoint_hash"],
             "covered_event_head_sequence" => event["sequence"],
             "covered_event_head_hash" => event_hash
           },
           %{
             "resource_hash" => member.resource_hash,
             "wrap_body_hash" => member.wrap_body_hash,
             "wrap_event_body_hash" => hash(event["body"]),
             "wrap_event_hash" => event_hash,
             "hpke_info_hash" => member.hpke_info_hash,
             "aad_hash" => member.aad_hash
           },
           "workspace_genesis"
         ), device_private, device_public}

      "genesis_device_bootstrap" ->
        [user_scope, workspace_scope] = intent["scopes"]
        user_device = find_effect(user_scope, "device_key_added")
        workspace_device = find_effect(workspace_scope, "device_key_added")
        owner_member = find_effect(workspace_scope, "member_added")

        links = %{
          user_device_key_added_event_hash: user_device["event_hash"],
          workspace_device_key_added_event_hash: workspace_device["event_hash"],
          owner_user_id: prepare["user_id"],
          owner_role_id: prepare["owner_role_id"],
          owner_member_added_event_hash: owner_member["event_hash"],
          workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash
        }

        context_hash =
          Intent.compound_context_hash!(
            genesis.registration_id,
            prepared.prepare_request_hash,
            intent,
            links
          )

        {Signature.build_genesis_device_bootstrap_transcript!(%{
           registration_id: genesis.registration_id,
           compound_intent_id: intent["compound_intent_id"],
           mutation_id: intent["mutation_id"],
           genesis_compound_context_hash: context_hash,
           user_id: prepare["user_id"],
           workspace_id: prepare["workspace_id"],
           owner_role_id: prepare["owner_role_id"],
           device_id: prepare["device_id"],
           device_public_material: prepare["device_hybrid_signing_public_key_material"],
           device_hybrid_encryption_public_key_material:
             prepare["device_hybrid_encryption_public_key_material"],
           client_nonce: prepare["client_nonce"],
           registration_challenge_hash: Hash.blake3_base64url(challenge.challenge),
           identity_signing_key_id: prepared.identity_signing_key_id,
           user_identity_public_key_hash:
             hash(prepare["identity_hybrid_signing_public_key_material"]),
           user_device_key_added_event_hash: user_device["event_hash"],
           workspace_device_key_added_event_hash: workspace_device["event_hash"],
           owner_member_added_event_hash: owner_member["event_hash"],
           workspace_member_envelope_commitment_hash: prepared.member_envelope.commitment_hash,
           user_audit_checkpoint: %{
             "sequence" => 2,
             "checkpoint_hash" => user_scope["checkpoint_payload_hash"]
           },
           workspace_audit_checkpoint: %{
             "sequence" => 1,
             "checkpoint_hash" => workspace_scope["checkpoint_payload_hash"]
           }
         }), identity_private, identity_public}
    end
  end

  defp audit_checkpoint_payload(scope, prepare) do
    event = List.last(scope["candidate_events"])

    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => scope["chain_scope_kind"],
      "chain_scope_id" => scope["chain_scope_id"],
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "signer_user_id" => prepare["user_id"],
      "signing_key_id" =>
        if(scope["chain_scope_kind"] == "user",
          do: prepare["identity_signing_key_id"],
          else: prepare["device_signing_key_id"]
        ),
      "authorization_checkpoint_scope_kind" => scope["chain_scope_kind"],
      "authorization_checkpoint_scope_id" => scope["chain_scope_id"],
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => event["event_type"]
    }
    |> then(fn payload ->
      if scope["chain_scope_kind"] == "workspace",
        do: Map.put(payload, "signer_device_id", prepare["device_id"]),
        else: payload
    end)
  end

  defp checkpoint_signer(%{"chain_scope_kind" => "user"}, requirement, prepare) do
    %{
      "signer_kind" => "identity",
      "user_id" => prepare["user_id"],
      "signing_key_id" => requirement["signer_key_id"],
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }
  end

  defp checkpoint_signer(_scope, requirement, prepare) do
    %{
      "signer_kind" => "device",
      "user_id" => prepare["user_id"],
      "device_id" => prepare["device_id"],
      "signing_key_id" => requirement["signer_key_id"],
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }
  end

  defp find_effect(scope, event_type) do
    Enum.find(scope["candidate_key_directory_effects"], fn effect ->
      effect["event_payload"]["event_type"] == event_type
    end)
  end

  defp sign(purpose, transcript, private, public) do
    Signature.__test_sign_hybrid_signature__(purpose, transcript, private, public)
  end

  defp prepare_request(genesis, challenge) do
    user_id = genesis.reserved_user_id
    workspace_id = genesis.reserved_workspace_id
    device_id = Ecto.UUID.generate()
    identity_private = hybrid_signing_private_key_material("identity", user_id)
    identity_signing = hybrid_signing_public_key_material(identity_private)
    device_private = hybrid_signing_private_key_material("device", device_id)
    device_signing = hybrid_signing_public_key_material(device_private)
    {identity_x25519, _} = :crypto.generate_key(:ecdh, :x25519)
    {device_x25519, _} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", user_id, identity_x25519).public

    device_encryption =
      hybrid_encryption_public_key_material("device", device_id, device_x25519).public

    identity_signing_key_id = Signature.compute_signing_key_id!(identity_signing)

    identity_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(identity_encryption)

    device_signing_key_id = Signature.compute_signing_key_id!(device_signing)

    device_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(device_encryption)

    recovery_private = hybrid_signing_private_key_material("recovery_authorization", user_id)
    recovery_public = hybrid_signing_public_key_material(recovery_private)

    recovery = %{
      public: recovery_public,
      key_id: Signature.compute_signing_key_id!(recovery_public)
    }

    secret = secret_record(user_id, identity_signing_key_id, identity_encryption_key_id)

    policy = Suite.current_suite_policy()

    suite_policy = %{
      "suite_policy_version" => policy["suite_policy_version"],
      "min_suite_rank" => policy["min_suite_rank"],
      "allowed_suite_ids" => policy["allowed_suite_ids"]
    }

    wrap =
      genesis_wrap(
        user_id,
        workspace_id,
        device_id,
        device_signing_key_id,
        identity_encryption_key_id
      )

    %{
      "registration_id" => genesis.registration_id,
      "registration_challenge" => b64(challenge),
      "user_id" => user_id,
      "workspace_id" => workspace_id,
      "owner_role_id" => genesis.reserved_workspace_role_ids["owner"],
      "name" => "Browser",
      "device_type" => "browser",
      "device_id" => device_id,
      "encrypted_umk" => b64(:binary.copy(<<3>>, 32)),
      "encrypted_umk_nonce" => b64(:binary.copy(<<4>>, 24)),
      "recoverable_identity_secret_record" => secret,
      "identity_hybrid_signing_public_key_material" => identity_signing,
      "identity_signing_key_id" => identity_signing_key_id,
      "identity_hybrid_encryption_public_key_material" => identity_encryption,
      "identity_encryption_key_id" => identity_encryption_key_id,
      "device_hybrid_signing_public_key_material" => device_signing,
      "device_signing_key_id" => device_signing_key_id,
      "device_hybrid_encryption_public_key_material" => device_encryption,
      "device_encryption_key_id" => device_encryption_key_id,
      "recovery_authorization" => %{
        "recovery_encrypted_umk" => b64(:binary.copy(<<5>>, 32)),
        "recovery_nonce" => b64(:binary.copy(<<6>>, 24)),
        "recovery_authorization_key_id" => recovery.key_id,
        "recovery_authorization_public_material" => recovery.public
      },
      "initial_suite_policy" => suite_policy,
      "workspace_member_envelope_precommit" => %{
        "protocol" => "refmd.workspace-member-envelope",
        "version" => 1,
        "workspace_id" => workspace_id,
        "target_user_id" => user_id,
        "kek_version" => 1,
        "target_identity_encryption_key_id" => identity_encryption_key_id,
        "target_identity_key_material_hash" => hash(identity_encryption),
        "authorization_key_directory_checkpoint_sequence" => 1,
        "authorization_key_directory_checkpoint_hash" => "GENESIS",
        "wrap" => wrap
      },
      "client_nonce" => b64(:binary.copy(<<7>>, 16))
    }
  end

  defp secret_record(user_id, signing_key_id, encryption_key_id) do
    record_id = Ecto.UUID.generate()
    signing_ciphertext = :binary.copy(<<8>>, 32)
    signing_nonce = :binary.copy(<<9>>, 24)
    encryption_ciphertext = :binary.copy(<<10>>, 32)
    encryption_nonce = :binary.copy(<<11>>, 24)

    storage_scope = %{
      "kind" => "user_identity_key",
      "user_id" => user_id,
      "identity_key_epoch" => 1
    }

    signing_aad_hash =
      hash(%{
        "protocol" => "refmd.hybrid-signing-private-key-material-encryption",
        "version" => 1,
        "purpose" => "identity_hybrid_signing_private_key_material",
        "owner_kind" => "identity",
        "owner_id" => user_id,
        "signing_key_id" => signing_key_id,
        "suite_id" => "refmd-v2-hybrid-signature-ed25519-mldsa65",
        "suite_rank" => 1000,
        "storage_scope" => storage_scope
      })

    encryption_aad_hash =
      hash(%{
        "protocol" => "refmd.hybrid-encryption-private-key-material-encryption",
        "version" => 1,
        "purpose" => "identity_hybrid_encryption_private_key_material",
        "owner_kind" => "identity",
        "owner_id" => user_id,
        "encryption_key_id" => encryption_key_id,
        "suite_id" =>
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
        "suite_rank" => 1000,
        "storage_scope" => storage_scope
      })

    preimage = %{
      "protocol" => "refmd.recoverable-identity-secret-record",
      "version" => 1,
      "record_id" => record_id,
      "user_id" => user_id,
      "identity_key_epoch" => 1,
      "previous_record_hash" => "GENESIS",
      "signing_key_id" => signing_key_id,
      "encryption_key_id" => encryption_key_id,
      "signing_ciphertext_hash" => Hash.blake3_base64url(signing_ciphertext),
      "signing_nonce_hash" => Hash.blake3_base64url(signing_nonce),
      "signing_material_aad_hash" => signing_aad_hash,
      "encryption_ciphertext_hash" => Hash.blake3_base64url(encryption_ciphertext),
      "encryption_nonce_hash" => Hash.blake3_base64url(encryption_nonce),
      "encryption_material_aad_hash" => encryption_aad_hash
    }

    %{
      "id" => record_id,
      "user_id" => user_id,
      "identity_key_epoch" => 1,
      "previous_record_hash" => "GENESIS",
      "encrypted_identity_hybrid_signing_private_key_material" => b64(signing_ciphertext),
      "identity_hybrid_signing_private_key_material_nonce" => b64(signing_nonce),
      "encrypted_identity_hybrid_encryption_private_key_material" => b64(encryption_ciphertext),
      "identity_hybrid_encryption_private_key_material_nonce" => b64(encryption_nonce),
      "signing_key_id" => signing_key_id,
      "encryption_key_id" => encryption_key_id,
      "signing_material_aad_hash" => signing_aad_hash,
      "encryption_material_aad_hash" => encryption_aad_hash,
      "record_hash" => hash(preimage),
      "is_current" => true
    }
  end

  defp genesis_wrap(user_id, workspace_id, device_id, signing_key_id, encryption_key_id) do
    key_scope = %{
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => 0,
      "key_checkpoint_hash" => "GENESIS"
    }

    %{
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => 1,
      "suite_id" =>
        "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
      "suite_rank" => 1000,
      "purpose" => "workspace_member_kek_wrap",
      "resource" => %{
        "workspace_id" => workspace_id,
        "target_user_id" => user_id,
        "kek_version" => 1
      },
      "sender" =>
        Map.merge(key_scope, %{
          "signer_kind" => "device",
          "user_id" => user_id,
          "device_id" => device_id,
          "signing_key_id" => signing_key_id
        }),
      "recipient" =>
        Map.merge(key_scope, %{
          "recipient_kind" => "user_identity",
          "user_id" => user_id,
          "encryption_key_id" => encryption_key_id
        }),
      "event_scope" => %{"scope_kind" => "workspace", "scope_id" => workspace_id},
      "hpke" => %{
        "mode" => "base",
        "kem_id" => 25_722,
        "kdf_id" => 1,
        "aead_id" => 3,
        "enc" => b64(:binary.copy(<<12>>, 1120)),
        "ciphertext" => b64(:binary.copy(<<13>>, 48))
      }
    }
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp b64(value), do: Encoding.encode_base64url(value)
end
