defmodule RefMD.Devices.Revocations.Commit do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Devices.{Device, DeviceRevocationEvent}
  alias RefMD.Devices.Revocations.{Authorization, Intent}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{CompoundAppend, MutationOutbox}

  def commit(user_id, actor_device_id, device_id, authorization) when is_map(authorization) do
    intent_hash = authorization["intent_hash"]
    authorization_hash = CompoundAppend.hash(authorization)

    Repo.transaction(
      fn ->
        case CompoundAppend.replay_receipt(
               authorization["compound_intent_id"],
               authorization["mutation_id"],
               intent_hash,
               authorization_hash
             ) do
          {:ok, receipt} -> %{response: receipt.body, status: receipt.status, replay?: true}
          :not_found -> commit_new!(user_id, actor_device_id, device_id, authorization)
        end
      end,
      isolation: :serializable
    )
  rescue
    error in [ArgumentError, Ecto.InvalidChangesetError] -> {:error, error_message(error)}
  end

  def commit(_, _, _, _), do: {:error, :device_revocation_authorization_invalid}

  defp commit_new!(user_id, actor_device_id, device_id, authorization) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    {pending, intent, command} =
      CompoundAppend.lock_intent!(
        authorization["compound_intent_id"],
        authorization["mutation_id"],
        now
      )

    unless pending.actor_user_id == user_id and pending.actor_device_id == actor_device_id,
      do: Repo.rollback(:device_revocation_actor_mismatch)

    verified = Authorization.verify!(pending, intent, command, authorization, device_id)
    append_key_directory!(verified)
    mark_revoked!(user_id, device_id, now)
    cleanup!(user_id, device_id)
    revocation = insert_revocation!(verified, now)
    audit = insert_audit!(verified)

    response = %{
      "status" => "committed",
      "revoked_device_id" => device_id,
      "revocation_mode" => "retire",
      "user_key_directory_checkpoint_hash" =>
        verified.scope["candidate_key_directory_checkpoint_hash"],
      "user_audit_checkpoint_hash" => audit.signed_checkpoint.checkpoint_hash,
      "workspaces_needing_kek_rotation" => []
    }

    enqueue_outbox!(pending, audit, revocation, response, now)
    CompoundAppend.consume!(pending, intent, authorization, response, 200, now)
    %{response: response, status: 200, replay?: false}
  end

  defp append_key_directory!(verified) do
    scope = verified.scope
    authorizations = verified.effect_authorizations

    events =
      Enum.map(scope["candidate_key_directory_effects"], fn effect ->
        payload = effect["event_payload"]
        entry = Enum.at(authorizations, effect["effect_order"] - 1)

        %{
          "payload" => payload,
          "signatures" => [%{"signer" => payload["actor"], "signature" => entry["signature"]}]
        }
      end)

    checkpoint_auth =
      Enum.find(authorizations, &(&1["authorization_kind"] == "key_directory_checkpoint"))

    p = verified.prepared

    checkpoint = %{
      "payload" => scope["candidate_key_directory_checkpoint_payload"],
      "signatures" => [
        %{
          "signer" => %{
            "signer_kind" => "identity",
            "user_id" => p.user_id,
            "signing_key_id" => p.identity_signing_key_id,
            "authorizing_checkpoint_sequence" => p.key_checkpoint.sequence,
            "authorizing_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
          },
          "signature" => checkpoint_auth["signature"]
        }
      ]
    }

    Encryption.append_user_key_directory!(p.user_id, events, checkpoint,
      checkpoint_signer_kind: "identity"
    )
  end

  defp mark_revoked!(user_id, device_id, now) do
    case from(d in Device,
           where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
         )
         |> Repo.update_all(set: [revoked_at: now]) do
      {1, _} -> :ok
      _ -> Repo.rollback(:device_revocation_target_invalid)
    end
  end

  defp cleanup!(user_id, device_id) do
    RefMD.Auth.delete_device_sessions(device_id)
    RefMD.Auth.delete_device_rrp_challenges(device_id)
    {user_id, device_id}
  end

  defp insert_revocation!(verified, now) do
    p = verified.prepared

    signature =
      verified.effect_authorizations
      |> Enum.find(&(&1["authorization_kind"] == "device_revocation"))
      |> Map.fetch!("signature")

    %DeviceRevocationEvent{created_at: now}
    |> DeviceRevocationEvent.changeset(%{
      user_id: p.user_id,
      device_id: p.target_device_id,
      revoked_by_device_id: p.actor_device_id,
      revocation_mode: "retire",
      signature: signature,
      revoked_at: DateTime.to_unix(now, :millisecond)
    })
    |> Repo.insert!()
  end

  defp insert_audit!(verified) do
    p = verified.prepared
    event = List.first(verified.scope["candidate_events"])
    actor = event["event_body"]["actor"]

    attrs = %{
      event_id: event["event_id"],
      class: "authority",
      type: event["event_type"],
      event_body: event["event_body"],
      actor: %{
        "user_id" => actor["user_id"],
        "device_id" => actor["device_id"],
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => actor["user_id"]
      },
      scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => "user_device", "id" => p.target_device_id, "version_hash" => nil},
      action: %{"operation" => event["event_type"], "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }

    checkpoint = %{
      "payload" => Intent.audit_checkpoint_payload(p, event),
      "signature" => verified.scope_signature["signature"],
      "checkpoint_hash" => verified.scope_signature["checkpoint_hash"]
    }

    case Security.record_signed_audit_events([attrs], checkpoint) do
      {:ok, result} -> result
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp enqueue_outbox!(pending, audit, _revocation, response, now) do
    event = List.last(audit.audit_events)

    MutationOutbox.build!(
      pending.compound_intent_id,
      pending.mutation_id,
      "pubsub_broadcast",
      %{"topic" => "device_revocation:#{pending.actor_user_id}", "audit_event_id" => event.id},
      response,
      now
    )
    |> then(&MutationOutbox.enqueue_all!([&1]))
  end

  defp error_message(%Ecto.InvalidChangesetError{} = error), do: error.changeset
  defp error_message(%ArgumentError{} = error), do: error.message
end
