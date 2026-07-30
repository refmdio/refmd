defmodule RefMD.Workspaces.Genesis.Commit do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Encryption
  alias RefMD.Encryption.{RotationPolicy, WorkspaceMemberEnvelope}
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.CompoundAppend
  alias RefMD.Workspaces.Genesis.Authorization
  alias RefMD.Workspaces.{Workspace, WorkspaceMember, WorkspaceRole}

  def commit(user_id, device_id, authorization) when is_map(authorization) do
    compound_intent_id = authorization["compound_intent_id"]
    mutation_id = authorization["mutation_id"]
    intent_hash = authorization["intent_hash"]
    authorization_hash = CompoundAppend.hash(authorization)

    Repo.transaction(
      fn ->
        case CompoundAppend.replay_receipt(
               compound_intent_id,
               mutation_id,
               intent_hash,
               authorization_hash
             ) do
          {:ok, receipt} ->
            %{response: receipt.body, status: receipt.status, replay?: true}

          :not_found ->
            commit_new!(user_id, device_id, authorization)
        end
      end,
      isolation: :serializable
    )
  rescue
    error in [ArgumentError, Ecto.InvalidChangesetError] -> {:error, error_message(error)}
  end

  def commit(_, _, _), do: {:error, :workspace_genesis_authorization_invalid}

  defp commit_new!(user_id, device_id, authorization) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    {pending, intent, command} =
      CompoundAppend.lock_intent!(
        authorization["compound_intent_id"],
        authorization["mutation_id"],
        now
      )

    unless pending.actor_user_id == user_id and pending.actor_device_id == device_id,
      do: Repo.rollback(:workspace_genesis_actor_mismatch)

    verified = Authorization.verify!(pending, intent, command, authorization)
    workspace = insert_workspace!(verified.prepared, now)
    insert_key_directory!(verified)
    insert_member_envelope!(verified, now)
    audit = insert_audit!(verified)

    response = %{
      "status" => "committed",
      "workspace_id" => workspace.id,
      "workspace_audit_checkpoint" => audit.signed_checkpoint
    }

    CompoundAppend.consume!(pending, intent, authorization, response, 201, now)
    %{response: response, status: 201, replay?: false}
  end

  defp insert_workspace!(p, now) do
    slug = generate_slug(p.command["name"])

    workspace =
      %Workspace{
        id: p.workspace_id,
        current_kek_version: 1,
        min_kek_version: 1,
        kek_rotation_due_at: RotationPolicy.next_kek_due_at()
      }
      |> Workspace.changeset(%{
        name: p.command["name"],
        slug: slug,
        description: p.command["description"],
        icon: p.command["icon"],
        owner_id: p.user_id
      })
      |> Repo.insert!()

    roles =
      Enum.map(
        [
          {"owner", "Owner"},
          {"admin", "Admin"},
          {"editor", "Editor"},
          {"viewer", "Viewer"},
          {"guest", "Guest"}
        ],
        fn {base_role, name} ->
          role =
            if base_role == "owner",
              do: %WorkspaceRole{id: p.owner_role_id, created_at: now},
              else: %WorkspaceRole{created_at: now}

          role
          |> WorkspaceRole.changeset(%{
            workspace_id: workspace.id,
            name: name,
            base_role: base_role,
            is_default: base_role == "editor"
          })
          |> Repo.insert!()
        end
      )

    owner_role = Enum.find(roles, &(&1.base_role == "owner"))

    %WorkspaceMember{joined_at: now}
    |> WorkspaceMember.changeset(%{
      workspace_id: workspace.id,
      user_id: p.user_id,
      role_id: owner_role.id,
      is_default: false,
      joined_at: now
    })
    |> Repo.insert!()

    workspace
  end

  defp insert_key_directory!(verified) do
    scope = verified.scope
    entries = verified.effect_authorizations

    events =
      scope["candidate_key_directory_effects"]
      |> Enum.map(fn effect ->
        entry = Enum.at(entries, effect["effect_order"] - 1)
        payload = effect["event_payload"]

        %{
          "payload" => payload,
          "signatures" => [%{"signer" => payload["actor"], "signature" => entry["signature"]}]
        }
      end)

    checkpoint_entry =
      Enum.find(entries, &(&1["authorization_kind"] == "key_directory_checkpoint"))

    checkpoint = %{
      "payload" => scope["candidate_key_directory_checkpoint_payload"],
      "signatures" => [
        %{
          "signer" => %{
            "signer_kind" => "device",
            "user_id" => verified.prepared.user_id,
            "device_id" => verified.prepared.device_id,
            "signing_key_id" => verified.prepared.device_signing_key_id,
            "authorizing_checkpoint_sequence" => 0,
            "authorizing_checkpoint_hash" => "GENESIS"
          },
          "signature" => checkpoint_entry["signature"]
        }
      ]
    }

    Encryption.insert_initial_workspace_key_directory!(
      verified.prepared.workspace_id,
      events,
      checkpoint,
      checkpoint_signer_kind: "device"
    )
  end

  defp insert_member_envelope!(verified, now) do
    scope = verified.scope
    p = verified.prepared
    event = List.last(scope["candidate_key_directory_effects"])
    event_payload = event["event_payload"]
    checkpoint = scope["candidate_key_directory_checkpoint_payload"]
    covered = checkpoint["covered_event_head"]
    wrap = p.command["workspace_member_envelope_precommit"]["wrap"]
    pq = Enum.find(verified.effect_authorizations, &(&1["authorization_kind"] == "pq_wrap"))
    signature = pq["signature"]

    envelope =
      wrap
      |> Map.put("event", %{
        "wrap_event_sequence" => event_payload["sequence"],
        "wrap_event_hash" => event["event_hash"],
        "wrap_event_body_hash" => hash(event_payload["body"])
      })
      |> Map.put("operation_checkpoint", %{
        "checkpoint_sequence" => checkpoint["sequence"],
        "checkpoint_hash" => scope["candidate_key_directory_checkpoint_hash"],
        "covered_event_head_sequence" => covered["head_sequence"],
        "covered_event_head_hash" => covered["head_hash"]
      })
      |> Map.put("transcript_hash", signature["transcript_hash"])
      |> Map.put("signature", signature)
      |> Map.merge(%{
        "target_user_id" => p.user_id,
        "sender_device_id" => p.device_id,
        "key_version" => 1
      })

    attrs =
      envelope
      |> SignedPQ.attrs_from_container_params!()
      |> Map.merge(%{
        workspace_id: p.workspace_id,
        target_user_id: p.user_id,
        sender_device_id: p.device_id,
        key_version: 1
      })

    unless event_payload["body"]["workspace_member_envelope_hash"] ==
             p.member_envelope.commitment_hash,
           do: Repo.rollback(:workspace_genesis_member_envelope_mismatch)

    %WorkspaceMemberEnvelope{created_at: now}
    |> WorkspaceMemberEnvelope.changeset(attrs)
    |> Repo.insert!()
  end

  defp insert_audit!(verified) do
    scope = verified.scope
    event = List.first(scope["candidate_events"])
    actor = event["event_body"]["actor"]

    attrs = %{
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
      scope: %{"workspace_id" => event["chain_scope_id"], "document_id" => nil, "share_id" => nil},
      resource: %{
        "kind" => "workspace",
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

    payload = audit_checkpoint_payload(verified.prepared, event)

    checkpoint = %{
      "payload" => payload,
      "signature" => verified.scope_signature["signature"],
      "checkpoint_hash" => verified.scope_signature["checkpoint_hash"]
    }

    case Security.record_signed_audit_events([attrs], checkpoint, [],
           genesis_candidate_authority: %{
             chain_scope_kind: "workspace",
             chain_scope_id: verified.prepared.workspace_id,
             signer_user_id: verified.prepared.user_id,
             signer_device_id: verified.prepared.device_id,
             public_key_material: verified.prepared.device_signing_material
           }
         ) do
      {:ok, result} -> result
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp audit_checkpoint_payload(p, event) do
    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => p.workspace_id,
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "signer_user_id" => p.user_id,
      "signer_device_id" => p.device_id,
      "signing_key_id" => p.device_signing_key_id,
      "authorization_checkpoint_scope_kind" => "workspace",
      "authorization_checkpoint_scope_id" => p.workspace_id,
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => "workspace.genesis"
    }
  end

  defp generate_slug(name) do
    base =
      name
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")

    base = if base == "", do: "workspace", else: base
    suffix = :crypto.strong_rand_bytes(4) |> Base.url_encode64(padding: false)
    "#{base}-#{String.downcase(suffix)}"
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp error_message(%Ecto.InvalidChangesetError{} = error), do: error.changeset
  defp error_message(%ArgumentError{} = error), do: error.message
end
