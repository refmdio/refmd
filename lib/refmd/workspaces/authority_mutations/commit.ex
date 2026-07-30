defmodule RefMD.Workspaces.AuthorityMutations.Commit do
  @moduledoc false

  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{CompoundAppend, MutationOutbox}
  alias RefMD.Workspaces.AuthorityMutations.{Authorization, Intent}
  alias RefMD.Workspaces.KekRotation
  alias RefMD.Workspaces.KekRotation.Directory
  alias RefMD.Workspaces.Members

  def commit(actor_user_id, actor_device_id, authorization, expected_binding \\ %{})

  def commit(actor_user_id, actor_device_id, authorization, expected_binding)
      when is_map(authorization) and is_map(expected_binding) do
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
          {:ok, receipt} ->
            %{response: receipt.body, status: receipt.status, replay?: true}

          :not_found ->
            commit_new!(actor_user_id, actor_device_id, authorization, expected_binding)
        end
      end,
      isolation: :serializable
    )
  rescue
    error in [ArgumentError, Ecto.InvalidChangesetError] -> {:error, error_message(error)}
  end

  def commit(_, _, _, _), do: {:error, :workspace_authority_mutation_authorization_invalid}

  defp commit_new!(actor_user_id, actor_device_id, authorization, expected_binding) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    {pending, intent, command} =
      CompoundAppend.lock_intent!(
        authorization["compound_intent_id"],
        authorization["mutation_id"],
        now
      )

    expected_mutation_kind = Map.get(expected_binding, "mutation_kind")
    expected_command_binding = Map.delete(expected_binding, "mutation_kind")

    unless (is_nil(expected_mutation_kind) or pending.mutation_kind == expected_mutation_kind) and
             Map.take(command, Map.keys(expected_command_binding)) == expected_command_binding,
           do: Repo.rollback(:workspace_authority_mutation_route_binding_mismatch)

    unless pending.actor_user_id == actor_user_id and pending.actor_device_id == actor_device_id,
      do: Repo.rollback(:workspace_authority_mutation_actor_mismatch)

    verified = Authorization.verify!(pending, intent, command, authorization)
    append_key_directory!(verified)
    business = apply_business!(pending.mutation_kind, verified)
    audit = insert_audit!(verified)

    response =
      %{
        "status" => "committed",
        "event_type" => pending.mutation_kind,
        "workspace_id" => verified.prepared.workspace_id,
        "workspace_key_directory_checkpoint_hash" =>
          verified.scope["candidate_key_directory_checkpoint_hash"],
        "workspace_audit_checkpoint_hash" => audit.signed_checkpoint.checkpoint_hash,
        "permission_loss" => Map.get(business, :permission_loss?, false),
        "workspaces_needing_kek_rotation" => []
      }
      |> Map.merge(Map.get(business, :response_fields, %{}))

    enqueue_outbox!(pending, verified, audit, response, now)
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

    checkpoint = %{
      "payload" => scope["candidate_key_directory_checkpoint_payload"],
      "signatures" => [
        %{
          "signer" => Intent.checkpoint_signer(verified.prepared),
          "signature" => checkpoint_auth["signature"]
        }
      ]
    }

    Encryption.append_workspace_key_directory!(verified.prepared.workspace_id, events, checkpoint,
      checkpoint_signer_kind: "device"
    )
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp apply_business!("workspace.member.role_changed", %{prepared: p}) do
    result =
      Members.apply_role_change!(
        p.workspace_id,
        p.command["target_user_id"],
        p.command["new_role_id"],
        p.actor_user_id
      )

    Map.put(result, :response_fields, rotation_response_fields(p.workspace_id))
  end

  defp apply_business!("workspace.member.removed", %{prepared: p}) do
    %{
      member:
        Members.apply_removal!(p.workspace_id, p.command["target_user_id"], p.actor_user_id),
      response_fields: rotation_response_fields(p.workspace_id)
    }
  end

  defp apply_business!("workspace.kek.rotation_started", %{prepared: p}) do
    %{
      workspace:
        KekRotation.apply_start!(
          p.workspace_id,
          p.actor_user_id,
          p.command["rotation_id"],
          p.command["new_key_version"]
        )
    }
  end

  defp apply_business!("workspace.kek.rotation_completed", %{scope: scope} = verified) do
    completed_event_hash =
      scope["candidate_key_directory_effects"] |> hd() |> Map.fetch!("event_hash")

    workspace = KekRotation.apply_completion!(verified, completed_event_hash)
    old_key_version = verified.prepared.command["old_key_version"]
    covered = scope["candidate_key_directory_checkpoint_payload"]["covered_event_head"]

    %{
      workspace: workspace,
      response_fields:
        Map.merge(
          %{
            "rotation_completed_event_hash" => completed_event_hash,
            "server_rejects_old_key_uploads_after_sequence" => covered["head_sequence"]
          },
          Directory.old_key_deletion_material(
            workspace.id,
            old_key_version
          )
        )
    }
  end

  defp apply_business!("workspace.kek.old_key_deleted", %{prepared: p, scope: scope}) do
    deleted_event_hash =
      scope["candidate_key_directory_effects"] |> hd() |> Map.fetch!("event_hash")

    %{
      workspace:
        KekRotation.apply_old_key_deletion!(p.command, p.actor_user_id, deleted_event_hash)
    }
  end

  defp rotation_response_fields(workspace_id) do
    rotations =
      KekRotation.list_workspaces_needing_kek_rotation()
      |> Enum.filter(&(&1.workspace_id == workspace_id))
      |> Enum.map(fn rotation ->
        Map.new(rotation, fn {key, value} -> {to_string(key), value} end)
      end)

    %{"workspaces_needing_kek_rotation" => rotations}
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
      scope: %{"workspace_id" => p.workspace_id, "document_id" => nil, "share_id" => nil},
      resource: %{
        "kind" => resource_kind(p.event_type),
        "id" => resource_id(p),
        "version_hash" => nil
      },
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

    case Security.record_signed_audit_events(
           [attrs],
           checkpoint,
           notifications(p, event["event_body"]["mutation_id"])
         ) do
      {:ok, result} -> result
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp notifications(%{event_type: event_type} = p, mutation_id) do
    recipient_ids =
      case event_type do
        "workspace.member.role_changed" -> [p.command["target_user_id"]]
        "workspace.member.removed" -> [p.command["target_user_id"]]
        _ -> Members.list_workspace_member_user_ids(p.workspace_id)
      end

    recipient_ids
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn recipient_id ->
      %{
        recipient_kind: "user",
        recipient_id: recipient_id,
        type: event_type,
        severity: notification_severity(event_type),
        action_ref: %{
          "workspace_id" => p.workspace_id,
          "mutation_id" => mutation_id
        },
        dedupe_key: "#{event_type}:#{p.workspace_id}:#{recipient_id}:#{mutation_id}"
      }
    end)
  end

  defp notification_severity("workspace.member.removed"), do: "critical"
  defp notification_severity("workspace.member.role_changed"), do: "warning"
  defp notification_severity("workspace.kek.old_key_deleted"), do: "warning"
  defp notification_severity(_event_type), do: "action_required"

  defp enqueue_outbox!(pending, verified, audit, response, now) do
    event = List.last(audit.audit_events)
    workspace_id = verified.prepared.workspace_id

    notification_items =
      Enum.map(audit.notifications, fn notification ->
        MutationOutbox.build!(
          pending.compound_intent_id,
          pending.mutation_id,
          "security_notification_delivery",
          %{
            "notification_id" => notification.id,
            "recipient_id" => notification.recipient_id,
            "recipient_kind" => notification.recipient_kind
          },
          Security.notification_outbox_payload(notification),
          now
        )
      end)

    broadcast_item =
      MutationOutbox.build!(
        pending.compound_intent_id,
        pending.mutation_id,
        "pubsub_broadcast",
        %{"topic" => "workspace:#{workspace_id}", "audit_event_id" => event.id},
        Map.put(response, "audit_event_id", event.id),
        now
      )

    MutationOutbox.enqueue_all!([broadcast_item | notification_items])
  end

  defp resource_kind(event_type)
       when event_type in [
              "workspace.kek.rotation_started",
              "workspace.kek.rotation_completed",
              "workspace.kek.old_key_deleted"
            ],
       do: "key_rotation"

  defp resource_kind(_), do: "workspace_member"

  defp resource_id(%{event_type: event_type} = p)
       when event_type in [
              "workspace.kek.rotation_started",
              "workspace.kek.rotation_completed",
              "workspace.kek.old_key_deleted"
            ],
       do: p.command["rotation_id"]

  defp resource_id(p), do: p.command["target_user_id"]

  defp error_message(%Ecto.InvalidChangesetError{} = error), do: error.changeset
  defp error_message(%ArgumentError{} = error), do: error.message
end
