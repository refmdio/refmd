defmodule RefMD.Security do
  @moduledoc """
  Application-wide security audit and notification plane.
  """

  import Ecto.Query

  alias Phoenix.PubSub
  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Devices
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Plugins.{PluginActivation, PluginApplication}
  alias RefMD.Repo
  alias RefMD.Security.{AuditEvent, Notification}
  alias RefMD.Workspaces

  @plugin_runtime_action_keys ~w(operation result reason_code)
  @plugin_runtime_network_action_keys @plugin_runtime_action_keys ++
                                        ~w(endpoint_id route method target_origin target_path request_bytes response_bytes credential_handle_used proxy_id fallback_reason)
  @plugin_runtime_network_event_types ~w(plugin.network.requested plugin.network.blocked)

  def record_audit_event(attrs, notifications \\ [])
      when is_map(attrs) and is_list(notifications) do
    case Repo.transaction(fn -> insert_audit_event_with_notifications(attrs, notifications) end) do
      {:ok, {audit_event, inserted}} ->
        Enum.each(inserted, &broadcast_notification/1)
        {:ok, %{audit_event: audit_event, notifications: inserted}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def current_audit_checkpoint(chain_scope) when is_binary(chain_scope) do
    with {:ok, %{sequence: sequence, event_hash: event_hash}} <- verify_audit_chain(chain_scope),
         %AuditEvent{} = event <- latest_audit_event(chain_scope),
         true <- event.sequence == sequence and event.event_hash == event_hash do
      audit_checkpoint(event)
    else
      nil -> nil
      _ -> {:error, :audit_chain_invalid}
    end
  end

  def current_audit_checkpoint!(chain_scope) when is_binary(chain_scope) do
    case current_audit_checkpoint(chain_scope) do
      checkpoint when is_map(checkpoint) -> checkpoint
      nil -> nil
      {:error, :audit_chain_invalid} -> raise "security audit chain verification failed"
    end
  end

  def notification_payload(%Notification{} = notification) do
    notification = Repo.preload(notification, :audit_event)

    checkpoint =
      case notification.audit_event do
        %AuditEvent{chain_scope: chain_scope} -> current_audit_checkpoint!(chain_scope)
        _ -> raise "security notification is missing its audit event"
      end

    Notification.payload(notification, checkpoint)
  end

  def verify_audit_chain(chain_scope) when is_binary(chain_scope) do
    events =
      Repo.all(
        from(e in AuditEvent,
          where: e.chain_scope == ^chain_scope,
          order_by: [asc: e.sequence]
        )
      )

    Enum.reduce_while(events, {:ok, nil, 0}, fn event, {:ok, previous_hash, sequence} ->
      expected_sequence = sequence + 1

      if event.sequence == expected_sequence and event.previous_event_hash == previous_hash and
           event.event_hash == audit_event_hash(event) do
        {:cont, {:ok, event.event_hash, event.sequence}}
      else
        {:halt, {:error, :audit_chain_invalid}}
      end
    end)
    |> case do
      {:ok, event_hash, sequence} ->
        {:ok, %{chain_scope: chain_scope, sequence: sequence, event_hash: event_hash}}

      error ->
        error
    end
  end

  def list_notifications(recipient_kind, recipient_id) do
    Repo.all(
      from(n in Notification,
        where: n.recipient_kind == ^recipient_kind and n.recipient_id == ^to_string(recipient_id),
        preload: [:audit_event],
        order_by: [desc: n.created_at]
      )
    )
  end

  def mark_notification_read(notification_id, recipient_kind, recipient_id) do
    update_notification_state(notification_id, recipient_kind, recipient_id, :read_at)
  end

  def dismiss_notification(notification_id, recipient_kind, recipient_id) do
    update_notification_state(notification_id, recipient_kind, recipient_id, :dismissed_at)
  end

  def subscribe_user(user_id), do: PubSub.subscribe(RefMD.PubSub, user_topic(user_id))

  def subscribe_pending_registration(registration_id),
    do: PubSub.subscribe(RefMD.PubSub, pending_registration_topic(registration_id))

  def subscribe_device(device_id), do: PubSub.subscribe(RefMD.PubSub, device_topic(device_id))

  def subscribe_workspace(workspace_id),
    do: PubSub.subscribe(RefMD.PubSub, workspace_topic(workspace_id))

  def broadcast_notification(%Notification{} = notification) do
    PubSub.broadcast(
      RefMD.PubSub,
      notification_topic(notification),
      {:security_notification, notification_payload(notification)}
    )
  end

  defp update_notification_state(notification_id, recipient_kind, recipient_id, field) do
    now = DateTime.utc_now()

    notification =
      Repo.one(
        from(n in Notification,
          where:
            n.id == ^notification_id and n.recipient_kind == ^recipient_kind and
              n.recipient_id == ^to_string(recipient_id)
        )
      )

    case notification do
      %Notification{} ->
        changes =
          case field do
            :read_at -> %{read_at: now}
            :dismissed_at -> %{dismissed_at: now}
          end

        updated =
          notification
          |> Ecto.Changeset.change(changes)
          |> Repo.update!()

        broadcast_notification(updated)
        {:ok, updated}

      nil ->
        {:error, :not_found}
    end
  end

  def record_device_registration_created(user_id, registration) do
    record_audit_event(
      authority_event(%{
        type: "device.registration.created",
        actor: user_actor(user_id, nil),
        scope: empty_scope(),
        resource: resource("device", registration.id, nil),
        operation: "device.registration.create",
        result: "completed",
        reason_code: nil,
        correlation: empty_correlation()
      }),
      [
        %{
          recipient_kind: "user",
          recipient_id: user_id,
          type: "device.pending_approval",
          severity: "action_required",
          action_ref: %{
            device_id: registration.id,
            name: registration.name,
            device_type: registration.device_type
          },
          dedupe_key: "device.pending_approval:#{registration.id}",
          expires_at: registration.expires_at
        }
      ]
    )
  end

  def record_device_registration_removed(user_id, registration_id) do
    result =
      record_audit_event(
        authority_event(%{
          type: "device.registration.removed",
          actor: user_actor(user_id, nil),
          scope: empty_scope(),
          resource: resource("device", registration_id, nil),
          operation: "device.registration.remove",
          result: "completed",
          reason_code: nil,
          correlation: empty_correlation()
        }),
        [
          %{
            recipient_kind: "user",
            recipient_id: user_id,
            type: "device.pending_removed",
            severity: "info",
            action_ref: %{device_id: registration_id},
            dedupe_key: "device.pending_removed:#{registration_id}"
          }
        ]
      )

    mark_device_pending_acted(user_id, registration_id)
    result
  end

  def record_registration_approved(user_id, registration_id) do
    record_registration_terminal(user_id, registration_id, "approved", "completed", nil)
  end

  def record_initial_ake_offers_ready(user_id, registration_id) do
    record_audit_event(
      authority_event(%{
        type: "device.registration.initial_ake_offers_ready",
        actor: user_actor(user_id, nil),
        scope: empty_scope(),
        resource: resource("device", registration_id, nil),
        operation: "device.registration.initial_ake_offers_ready",
        result: "completed",
        reason_code: nil,
        correlation: empty_correlation()
      }),
      [
        %{
          recipient_kind: "pending_registration",
          recipient_id: registration_id,
          type: "device.initial_ake_offers_ready",
          severity: "info",
          action_ref: %{device_id: registration_id},
          dedupe_key: "device.initial_ake_offers_ready:#{registration_id}"
        }
      ]
    )
  end

  def record_registration_rejected(user_id, registration_id) do
    record_registration_terminal(user_id, registration_id, "rejected", "denied", "user_rejected")
  end

  def record_registration_expired(user_id, registration_id) do
    record_registration_terminal(user_id, registration_id, "expired", "failed", "expired")
  end

  def record_kek_rotation_needed(user_id, workspace_id, current_kek_version) do
    record_audit_event(
      security_runtime_event(%{
        type: "workspace.kek_rotation_needed",
        actor: system_actor(),
        scope: workspace_scope(workspace_id),
        resource: resource("workspace", workspace_id, nil),
        operation: "workspace.kek_rotation.remind",
        result: "completed",
        reason_code: nil,
        correlation: empty_correlation()
      }),
      [
        %{
          recipient_kind: "user",
          recipient_id: user_id,
          type: "workspace.kek_rotation_needed",
          severity: "action_required",
          action_ref: %{
            workspace_id: workspace_id,
            current_kek_version: current_kek_version
          },
          dedupe_key: "workspace.kek_rotation_needed:#{workspace_id}:#{current_kek_version}"
        }
      ]
    )
  end

  def record_plugin_candidate_created(candidate) do
    record_audit_event(
      plugin_artifact_event(candidate, "plugin.bundle.candidate_created", "completed", nil)
    )
  end

  def record_plugin_artifact_validation_failed(attrs, reason) do
    record_audit_event(
      plugin_artifact_event(
        attrs,
        "plugin.artifact.validation_failed",
        "failed",
        to_string(reason)
      )
    )
  end

  def record_plugin_fetch_requested(attrs) do
    record_audit_event(
      plugin_artifact_event(attrs, "plugin.artifact.fetch_requested", "completed", nil)
    )
  end

  def record_plugin_fetch_completed(attrs) do
    record_audit_event(
      plugin_artifact_event(attrs, "plugin.artifact.fetch_completed", "completed", nil)
    )
  end

  def record_plugin_fetch_failed(attrs, reason) do
    record_audit_event(
      plugin_artifact_event(attrs, "plugin.artifact.fetch_failed", "failed", to_string(reason))
    )
  end

  def record_plugin_bundle_approved(bundle) do
    attrs = Map.from_struct(bundle)

    record_audit_event(
      plugin_bundle_event(
        attrs,
        "plugin.bundle.approved",
        user_actor(bundle.approved_by_user_id, bundle.approved_by_device_id),
        "plugin.bundle.approve",
        "completed",
        nil
      ),
      plugin_consent_required_notifications(bundle)
    )
  end

  def record_plugin_bundle_rejected(subject, approval_attrs, reason) do
    attrs = Map.merge(attrs_to_map(subject), approval_attrs)

    record_audit_event(
      plugin_bundle_event(
        attrs,
        "plugin.bundle.rejected",
        user_actor(Map.get(attrs, :approver_user_id), Map.get(attrs, :approver_device_id)),
        "plugin.bundle.reject",
        "denied",
        reason_code(reason)
      )
    )
  end

  def record_plugin_bundle_promoted(bundle) do
    attrs = Map.from_struct(bundle)

    record_audit_event(
      authority_event(%{
        type: "plugin.bundle.promoted",
        actor: user_actor(bundle.approved_by_user_id, bundle.approved_by_device_id),
        scope: workspace_scope(bundle.workspace_id),
        resource: plugin_resource(attrs),
        operation: "plugin.bundle.promote",
        result: "completed",
        reason_code: nil,
        sensitivity: empty_sensitivity(),
        correlation: %{
          "request_id" => nil,
          "capability_id" => nil,
          "execution_context_id" => nil,
          "authority_event_ref" => bundle.approval_event_hash,
          "candidate_id" => bundle.candidate_id
        }
      }),
      plugin_runtime_invalidation_notifications(bundle, "plugin.runtime_updated", "warning")
    )
  end

  def record_plugin_bundle_update_available(candidate) do
    record_audit_event(
      plugin_artifact_event(candidate, "plugin.bundle.update_available", "completed", nil)
    )
  end

  def record_plugin_application_disabled(application) do
    record_plugin_application_runtime_invalidation(
      application,
      "plugin.runtime_disabled",
      "plugin.runtime.disable"
    )
  end

  def record_plugin_application_updated(application) do
    application = Repo.preload(application, :current_bundle)
    bundle = application.current_bundle

    record_plugin_application_runtime_invalidation(
      application,
      "plugin.runtime_updated",
      "plugin.runtime.update",
      nil,
      plugin_application_consent_required_notifications(application, bundle)
    )
  end

  def record_plugin_application_uninstalled(application, activations \\ []) do
    record_plugin_application_runtime_invalidation(
      application,
      "plugin.runtime_uninstalled",
      "plugin.runtime.uninstall",
      activations
    )
  end

  def record_plugin_activation_disabled(activation, actor_device_id \\ nil) do
    activation = Repo.preload(activation, application: :current_bundle)
    application = activation.application
    bundle = application && application.current_bundle

    attrs = %{
      package_id: application && application.package_id,
      application_id: application && application.id,
      activation_id: activation.id,
      plugin_id: application && application.plugin_id,
      bundle_hash: bundle && bundle.bundle_hash
    }

    record_audit_event(
      authority_event(%{
        type: "plugin.runtime_disabled",
        actor: user_actor(activation.user_id, actor_device_id || activation.device_id),
        scope: workspace_scope(application && application.workspace_id),
        resource: plugin_resource(attrs),
        operation: "plugin.runtime.disable",
        result: "completed",
        reason_code: nil,
        sensitivity: empty_sensitivity(),
        correlation: empty_correlation()
      }),
      plugin_activation_disabled_notifications(activation, application, bundle)
    )
  end

  def record_plugin_activation_deleted(activation, actor_device_id \\ nil) do
    activation = Repo.preload(activation, application: :current_bundle)
    application = activation.application
    bundle = application && application.current_bundle

    attrs = %{
      package_id: application && application.package_id,
      application_id: application && application.id,
      activation_id: activation.id,
      plugin_id: application && application.plugin_id,
      bundle_hash: bundle && bundle.bundle_hash
    }

    record_audit_event(
      authority_event(%{
        type: "plugin.runtime_activation_deleted",
        actor: user_actor(activation.user_id, actor_device_id || activation.device_id),
        scope: workspace_scope(application && application.workspace_id),
        resource: plugin_resource(attrs),
        operation: "plugin.runtime.activation.delete",
        result: "completed",
        reason_code: nil,
        sensitivity: empty_sensitivity(),
        correlation: empty_correlation()
      }),
      plugin_activation_deleted_notifications(activation, application, bundle)
    )
  end

  defp plugin_consent_required_notifications(bundle) do
    if is_nil(bundle.workspace_id) or is_nil(bundle.application_id) do
      []
    else
      workspace_consent_required_notifications(bundle)
    end
  end

  defp workspace_consent_required_notifications(bundle) do
    bundle.workspace_id
    |> Workspaces.list_workspace_member_user_ids()
    |> Enum.map(fn user_id ->
      %{
        recipient_kind: "user",
        recipient_id: user_id,
        type: "plugin.consent_required",
        severity: "action_required",
        action_ref: %{
          workspace_id: bundle.workspace_id,
          application_id: bundle.application_id,
          plugin_id: bundle.plugin_id,
          bundle_hash: bundle.bundle_hash
        },
        dedupe_key:
          "plugin.consent_required:#{bundle.application_id}:#{bundle.bundle_hash}:#{user_id}"
      }
    end)
  end

  defp plugin_application_consent_required_notifications(
         %PluginApplication{} = application,
         bundle
       ) do
    if is_nil(bundle) do
      []
    else
      application.workspace_id
      |> Workspaces.list_workspace_member_user_ids()
      |> Enum.map(fn user_id ->
        %{
          recipient_kind: "user",
          recipient_id: user_id,
          type: "plugin.consent_required",
          severity: "action_required",
          action_ref: %{
            workspace_id: application.workspace_id,
            application_id: application.id,
            plugin_id: application.plugin_id,
            bundle_hash: bundle.bundle_hash
          },
          dedupe_key: "plugin.consent_required:#{application.id}:#{bundle.bundle_hash}:#{user_id}"
        }
      end)
    end
  end

  defp record_plugin_application_runtime_invalidation(
         application,
         type,
         operation,
         activations \\ nil,
         extra_notifications \\ []
       ) do
    bundle = Map.get(application, :current_bundle)

    attrs = %{
      plugin_id: application.plugin_id,
      bundle_hash: bundle && bundle.bundle_hash
    }

    record_audit_event(
      authority_event(%{
        type: type,
        actor: system_actor(),
        scope: workspace_scope(application.workspace_id),
        resource: plugin_resource(attrs),
        operation: operation,
        result: "completed",
        reason_code: nil,
        sensitivity: empty_sensitivity(),
        correlation: empty_correlation()
      }),
      plugin_runtime_invalidation_notifications(application, type, "warning", activations) ++
        extra_notifications
    )
  end

  defp plugin_runtime_invalidation_notifications(subject, type, severity),
    do: plugin_runtime_invalidation_notifications(subject, type, severity, nil)

  defp plugin_runtime_invalidation_notifications(subject, type, severity, activations) do
    workspace_id = subject.workspace_id
    application_id = runtime_invalidation_application_id(subject)
    package_id = Map.get(subject, :package_id)
    current_bundle = Map.get(subject, :current_bundle)
    bundle_hash = Map.get(subject, :bundle_hash) || (current_bundle && current_bundle.bundle_hash)

    if is_nil(workspace_id) or is_nil(application_id) do
      []
    else
      activations = activations || plugin_runtime_activations(application_id)

      workspace_id
      |> workspace_active_devices()
      |> Enum.map(fn device ->
        activation = plugin_runtime_activation_for_device(activations, device)

        %{
          recipient_kind: "device",
          recipient_id: device.id,
          type: type,
          severity: severity,
          action_ref:
            plugin_runtime_action_ref(%{
              workspace_id: workspace_id,
              package_id: package_id,
              application_id: application_id,
              activation_id: activation && activation.id,
              plugin_id: subject.plugin_id,
              bundle_hash: bundle_hash
            }),
          dedupe_key: "#{type}:#{application_id}:#{bundle_hash || "none"}:#{device.id}"
        }
      end)
    end
  end

  defp runtime_invalidation_application_id(%PluginApplication{id: id}), do: id
  defp runtime_invalidation_application_id(subject), do: Map.get(subject, :application_id)

  defp workspace_active_devices(workspace_id) do
    workspace_id
    |> Workspaces.list_workspace_member_user_ids()
    |> Enum.flat_map(fn user_id -> Devices.get_user_devices(user_id) end)
    |> Enum.uniq_by(& &1.id)
  end

  defp plugin_runtime_activations(application_id) do
    Repo.all(
      from(a in PluginActivation,
        where: a.application_id == ^application_id and is_nil(a.deleted_at),
        order_by: [desc: :created_at]
      )
    )
  end

  defp plugin_runtime_activation_for_device(activations, device) do
    Enum.find(activations, fn activation ->
      activation.user_id == device.user_id and
        (is_nil(activation.device_id) or activation.device_id == device.id)
    end)
  end

  defp plugin_runtime_action_ref(attrs) do
    attrs
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp plugin_activation_disabled_notifications(activation, application, bundle) do
    plugin_activation_notifications(activation, application, bundle, %{
      type: "plugin.runtime_disabled",
      dedupe_prefix: "plugin.runtime_disabled"
    })
  end

  defp plugin_activation_deleted_notifications(activation, application, bundle) do
    plugin_activation_notifications(activation, application, bundle, %{
      type: "plugin.runtime_activation_deleted",
      dedupe_prefix: "plugin.runtime_activation_deleted"
    })
  end

  defp plugin_activation_notifications(activation, application, bundle, attrs) do
    activation
    |> plugin_activation_recipient_devices()
    |> Enum.map(fn device ->
      %{
        recipient_kind: "device",
        recipient_id: device.id,
        type: attrs.type,
        severity: "warning",
        action_ref:
          plugin_runtime_action_ref(%{
            workspace_id: application && application.workspace_id,
            package_id: application && application.package_id,
            application_id: application && application.id,
            activation_id: activation.id,
            plugin_id: application && application.plugin_id,
            bundle_hash: bundle && bundle.bundle_hash
          }),
        dedupe_key:
          "#{attrs.dedupe_prefix}:#{activation.id}:#{(bundle && bundle.bundle_hash) || "none"}:#{device.id}"
      }
    end)
  end

  defp plugin_activation_recipient_devices(%PluginActivation{
         device_id: device_id,
         user_id: user_id
       })
       when is_binary(device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> [device]
      _ -> []
    end
  end

  defp plugin_activation_recipient_devices(%PluginActivation{user_id: user_id}) do
    Devices.get_user_devices(user_id)
  end

  def record_plugin_consent_event(event) do
    type =
      case event.decision do
        "allow" -> "plugin.consent.allowed"
        "deny" -> "plugin.consent.denied"
        "revoke" -> "plugin.consent.revoked"
      end

    notifications =
      if event.decision == "revoke" do
        [
          %{
            recipient_kind: "device",
            recipient_id: event.device_id,
            type: "plugin.runtime_revoked",
            severity: "warning",
            action_ref: %{
              workspace_id: event.workspace_id,
              package_id: event.package_id,
              application_id: event.application_id,
              activation_id: event.activation_id,
              plugin_id: event.plugin_id,
              bundle_hash: event.bundle_hash
            },
            dedupe_key:
              "plugin.runtime_revoked:#{event.application_id}:#{event.device_id}:#{event.event_hash}"
          }
        ]
      else
        []
      end

    result =
      record_audit_event(
        authority_event(%{
          type: type,
          actor: user_actor(event.user_id, event.device_id),
          scope: workspace_scope(event.workspace_id),
          resource: plugin_resource(Map.from_struct(event)),
          operation: "plugin.consent.#{event.decision}",
          result: "completed",
          reason_code: nil,
          sensitivity: empty_sensitivity(),
          correlation: %{
            "request_id" => nil,
            "capability_id" => nil,
            "execution_context_id" => nil,
            "authority_event_ref" => event.event_hash
          }
        }),
        notifications
      )

    mark_plugin_consent_required_acted(event)
    result
  end

  def record_plugin_runtime_event(attrs, user_id, device_id) when is_map(attrs) do
    record_audit_event(
      security_runtime_event(%{
        type: string_field(attrs, "type") || "plugin.runtime.event",
        actor: user_actor(user_id, device_id),
        scope: plugin_runtime_scope(attrs),
        resource: plugin_runtime_resource(attrs),
        operation: plugin_runtime_operation(attrs),
        result: plugin_runtime_result(attrs),
        reason_code: plugin_runtime_reason_code(attrs),
        action: plugin_runtime_action(attrs),
        sensitivity: Map.get(attrs, "sensitivity", empty_sensitivity()),
        correlation: plugin_runtime_correlation(attrs)
      })
    )
  end

  def security_runtime_event(attrs), do: event("security_runtime", attrs)

  def authority_event(attrs), do: event("authority", attrs)

  def empty_sensitivity do
    %{
      "plaintext_scope_kind" => "none",
      "plaintext_bytes" => 0,
      "egress_bytes" => 0,
      "storage_bytes" => 0
    }
  end

  defp insert_notifications(repo, audit_event, notifications) do
    Enum.reduce_while(notifications, {:ok, []}, fn attrs, {:ok, acc} ->
      attrs =
        attrs
        |> normalize_notification_attrs()
        |> Map.put(:audit_event_id, audit_event.id)

      changeset = Notification.changeset(%Notification{}, attrs)

      case repo.insert(changeset,
             on_conflict:
               {:replace,
                [:audit_event_id, :type, :severity, :action_ref, :expires_at, :created_at]},
             conflict_target: [:recipient_kind, :recipient_id, :dedupe_key],
             returning: true
           ) do
        {:ok, notification} -> {:cont, {:ok, [notification | acc]}}
        {:error, changeset} -> {:halt, {:error, changeset}}
      end
    end)
    |> case do
      {:ok, inserted} -> {:ok, Enum.reverse(inserted)}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp insert_audit_event_with_notifications(attrs, notifications) do
    attrs = normalize_audit_attrs(attrs)
    chain_scope = audit_chain_scope(attrs)
    lock_audit_chain!(chain_scope)
    ensure_audit_chain_valid!(chain_scope)
    previous = latest_audit_event(chain_scope, lock: true)
    sequence = if previous, do: previous.sequence + 1, else: 1

    attrs =
      attrs
      |> Map.put(:chain_scope, chain_scope)
      |> Map.put(:sequence, sequence)
      |> Map.put(:previous_event_hash, previous && previous.event_hash)
      |> then(&Map.put(&1, :event_hash, audit_event_hash(&1)))

    %AuditEvent{}
    |> AuditEvent.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, audit_event} -> insert_notifications_or_rollback(audit_event, notifications)
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp lock_audit_chain!(chain_scope) do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [chain_scope])
  end

  defp ensure_audit_chain_valid!(chain_scope) do
    case verify_audit_chain(chain_scope) do
      {:ok, _head} -> :ok
      {:error, :audit_chain_invalid} -> Repo.rollback(:audit_chain_invalid)
    end
  end

  defp latest_audit_event(chain_scope, opts \\ []) do
    query =
      from(e in AuditEvent,
        where: e.chain_scope == ^chain_scope,
        order_by: [desc: e.sequence],
        limit: 1
      )

    query =
      if Keyword.get(opts, :lock, false), do: from(e in query, lock: "FOR UPDATE"), else: query

    Repo.one(query)
  end

  defp audit_checkpoint(event) do
    %{
      chain_scope: event.chain_scope,
      sequence: event.sequence,
      event_hash: event.event_hash,
      ancestry: audit_checkpoint_ancestry(event.chain_scope),
      authority_checkpoint: audit_authority_checkpoint(event.chain_scope)
    }
  end

  defp audit_checkpoint_ancestry(chain_scope) do
    Repo.all(
      from(e in AuditEvent,
        where: e.chain_scope == ^chain_scope,
        order_by: [asc: e.sequence],
        select: %{
          protocol: "refmd.security-audit-chain",
          version: 1,
          chain_scope: e.chain_scope,
          sequence: e.sequence,
          previous_event_hash: e.previous_event_hash,
          event_hash: e.event_hash,
          class: e.class,
          type: e.type,
          actor: e.actor,
          scope: e.scope,
          resource: e.resource,
          action: e.action,
          sensitivity: e.sensitivity,
          correlation: e.correlation
        }
      )
    )
  end

  defp audit_authority_checkpoint(chain_scope) do
    with [scope_kind, scope_id] <- String.split(chain_scope, ":", parts: 2),
         true <- scope_kind in ["user", "workspace"],
         checkpoint when not is_nil(checkpoint) <-
           KeyDirectory.current_checkpoint(scope_kind, scope_id) do
      %{payload: checkpoint.payload, signatures: checkpoint.signatures}
    else
      _ -> nil
    end
  end

  defp audit_chain_scope(attrs) do
    scope = Map.fetch!(attrs, :scope)
    actor = Map.fetch!(attrs, :actor)
    resource = Map.fetch!(attrs, :resource)

    cond do
      present?(scope["workspace_id"]) ->
        "workspace:#{scope["workspace_id"]}"

      present?(scope["document_id"]) ->
        "document:#{scope["document_id"]}"

      present?(scope["share_id"]) ->
        "share:#{scope["share_id"]}"

      present?(actor["user_id"]) ->
        "user:#{actor["user_id"]}"

      present?(resource["kind"]) and present?(resource["id"]) ->
        "resource:#{resource["kind"]}:#{resource["id"]}"

      true ->
        "global:#{attrs.class}"
    end
  end

  defp present?(value), do: is_binary(value) and value != ""

  defp audit_event_hash(%AuditEvent{} = event), do: audit_event_hash(Map.from_struct(event))

  defp audit_event_hash(attrs) do
    preimage =
      %{
        "protocol" => "refmd.security-audit-chain",
        "version" => 1,
        "chain_scope" => field(attrs, :chain_scope),
        "sequence" => field(attrs, :sequence),
        "previous_event_hash" => field(attrs, :previous_event_hash),
        "class" => field(attrs, :class),
        "type" => field(attrs, :type),
        "actor" => field(attrs, :actor),
        "scope" => field(attrs, :scope),
        "resource" => field(attrs, :resource),
        "action" => field(attrs, :action),
        "sensitivity" => field(attrs, :sensitivity),
        "correlation" => field(attrs, :correlation)
      }
      |> compact_canonical_value()

    Hash.blake3_base64url(JCS.canonical_bytes!(preimage))
  end

  defp field(attrs, key), do: Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))

  defp compact_canonical_value(%{} = value) do
    value
    |> Enum.reject(fn {_key, nested} -> is_nil(nested) end)
    |> Map.new(fn {key, nested} -> {to_string(key), compact_canonical_value(nested)} end)
  end

  defp compact_canonical_value(value) when is_list(value),
    do: Enum.map(value, &compact_canonical_value/1)

  defp compact_canonical_value(value), do: value

  defp insert_notifications_or_rollback(audit_event, notifications) do
    case insert_notifications(Repo, audit_event, notifications) do
      {:ok, inserted} -> {audit_event, inserted}
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp record_registration_terminal(user_id, registration_id, terminal, result, reason_code) do
    result =
      record_audit_event(
        authority_event(%{
          type: "device.registration.#{terminal}",
          actor: user_actor(user_id, nil),
          scope: empty_scope(),
          resource: resource("device", registration_id, nil),
          operation: "device.registration.#{terminal}",
          result: result,
          reason_code: reason_code,
          correlation: empty_correlation()
        }),
        [
          %{
            recipient_kind: "pending_registration",
            recipient_id: registration_id,
            type: "device.registration_#{terminal}",
            severity: if(terminal == "approved", do: "info", else: "warning"),
            action_ref: %{device_id: registration_id},
            dedupe_key: "device.registration_#{terminal}:#{registration_id}"
          }
        ]
      )

    mark_device_pending_acted(user_id, registration_id)
    result
  end

  defp event(class, attrs) do
    %{
      class: class,
      type: Map.fetch!(attrs, :type),
      actor: Map.get(attrs, :actor, system_actor()),
      scope: Map.get(attrs, :scope, empty_scope()),
      resource: Map.fetch!(attrs, :resource),
      action: Map.get(attrs, :action) || base_action(attrs),
      sensitivity: Map.get(attrs, :sensitivity, empty_sensitivity()),
      correlation: Map.get(attrs, :correlation, empty_correlation())
    }
  end

  defp base_action(attrs) do
    %{
      "operation" => Map.fetch!(attrs, :operation),
      "result" => Map.fetch!(attrs, :result),
      "reason_code" => Map.get(attrs, :reason_code)
    }
  end

  defp plugin_artifact_event(attrs, type, result, reason_code) do
    attrs = attrs_to_map(attrs)

    security_runtime_event(%{
      type: type,
      actor:
        user_actor(Map.get(attrs, :created_by_user_id), Map.get(attrs, :created_by_device_id)),
      scope: workspace_scope(Map.get(attrs, :workspace_id)),
      resource: plugin_resource(attrs),
      operation: type,
      result: result,
      reason_code: reason_code,
      sensitivity: empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil,
        "candidate_id" => Map.get(attrs, :id),
        "source_kind" => Map.get(attrs, :source_kind),
        "canonical_source_host" => canonical_source_host(Map.get(attrs, :source_url)),
        "archive_hash" => Map.get(attrs, :archive_hash),
        "bundle_hash" => Map.get(attrs, :bundle_hash),
        "manifest_hash" => Map.get(attrs, :manifest_hash),
        "permissions_hash" => Map.get(attrs, :permissions_hash),
        "endpoint_hash" => Map.get(attrs, :endpoint_hash)
      }
    })
  end

  defp plugin_bundle_event(attrs, type, actor, operation, result, reason_code) do
    attrs = attrs_to_map(attrs)

    authority_event(%{
      type: type,
      actor: actor,
      scope: workspace_scope(Map.get(attrs, :workspace_id)),
      resource: plugin_resource(attrs),
      operation: operation,
      result: result,
      reason_code: reason_code,
      sensitivity: empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => Map.get(attrs, :approval_event_hash),
        "candidate_id" => Map.get(attrs, :candidate_id) || Map.get(attrs, :id),
        "source_kind" => Map.get(attrs, :source_kind),
        "canonical_source_host" => canonical_source_host(Map.get(attrs, :source_url)),
        "archive_hash" => Map.get(attrs, :archive_hash),
        "bundle_hash" => Map.get(attrs, :bundle_hash),
        "manifest_hash" => Map.get(attrs, :manifest_hash),
        "permissions_hash" => Map.get(attrs, :permissions_hash),
        "endpoint_hash" => Map.get(attrs, :endpoint_hash)
      }
    })
  end

  defp plugin_resource(attrs) do
    %{
      "kind" => "plugin",
      "id" => Map.get(attrs, :plugin_id),
      "version_hash" => Map.get(attrs, :bundle_hash)
    }
  end

  defp resource(kind, id, version_hash) do
    %{"kind" => kind, "id" => id, "version_hash" => version_hash}
  end

  defp workspace_scope(nil), do: empty_scope()

  defp workspace_scope(workspace_id),
    do: %{"workspace_id" => workspace_id, "document_id" => nil, "share_id" => nil}

  defp empty_scope, do: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil}

  defp empty_correlation do
    %{
      "request_id" => nil,
      "capability_id" => nil,
      "execution_context_id" => nil,
      "authority_event_ref" => nil
    }
  end

  defp string_field(attrs, key) do
    case Map.get(attrs, key) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp plugin_runtime_scope(attrs) do
    %{
      "workspace_id" => string_field(attrs, "workspace_id"),
      "document_id" => get_in(attrs, ["scope", "document_id"]),
      "share_id" => nil
    }
  end

  defp plugin_runtime_resource(attrs) do
    plugin_id = string_field(attrs, "plugin_id")
    bundle_hash = string_field(attrs, "bundle_hash")

    attrs
    |> get_in(["resource", "kind"])
    |> Kernel.||("plugin")
    |> resource(
      get_in(attrs, ["resource", "id"]) || plugin_id,
      get_in(attrs, ["resource", "version_hash"]) || bundle_hash
    )
    |> Map.merge(plugin_runtime_owner_identity(attrs))
  end

  defp plugin_runtime_operation(attrs) do
    get_in(attrs, ["action", "operation"]) || string_field(attrs, "operation") ||
      "plugin.runtime"
  end

  defp plugin_runtime_result(attrs), do: get_in(attrs, ["action", "result"]) || "completed"

  defp plugin_runtime_reason_code(attrs) do
    get_in(attrs, ["action", "reason_code"]) || string_field(attrs, "reasonCode")
  end

  defp plugin_runtime_action(attrs) do
    action =
      attrs
      |> Map.get("action", %{})
      |> case do
        action when is_map(action) -> Map.take(action, plugin_runtime_allowed_action_keys(attrs))
        _ -> %{}
      end

    action
    |> Map.merge(%{
      "operation" => plugin_runtime_operation(attrs),
      "result" => plugin_runtime_result(attrs),
      "reason_code" => plugin_runtime_reason_code(attrs)
    })
  end

  defp plugin_runtime_allowed_action_keys(attrs) do
    if string_field(attrs, "type") in @plugin_runtime_network_event_types do
      @plugin_runtime_network_action_keys
    else
      @plugin_runtime_action_keys
    end
  end

  defp plugin_runtime_correlation(attrs) do
    %{
      "request_id" =>
        get_in(attrs, ["correlation", "request_id"]) || string_field(attrs, "requestId"),
      "capability_id" =>
        get_in(attrs, ["correlation", "capability_id"]) ||
          string_field(attrs, "capability_id"),
      "execution_context_id" =>
        get_in(attrs, ["correlation", "execution_context_id"]) ||
          string_field(attrs, "executionContextId"),
      "authority_event_ref" => get_in(attrs, ["correlation", "authority_event_ref"]),
      "package_id" => string_field(attrs, "package_id"),
      "application_id" => string_field(attrs, "application_id"),
      "activation_id" => string_field(attrs, "activation_id"),
      "owner_scope_kind" => string_field(attrs, "owner_scope_kind"),
      "capability_grant_id" => string_field(attrs, "capability_grant_id"),
      "frame_generation" => Map.get(attrs, "frame_generation")
    }
  end

  defp plugin_runtime_owner_identity(attrs) do
    %{
      "plugin_id" => string_field(attrs, "plugin_id"),
      "package_id" => string_field(attrs, "package_id"),
      "application_id" => string_field(attrs, "application_id"),
      "activation_id" => string_field(attrs, "activation_id"),
      "owner_scope_kind" => string_field(attrs, "owner_scope_kind"),
      "capability_grant_id" => string_field(attrs, "capability_grant_id"),
      "bundle_hash" => string_field(attrs, "bundle_hash"),
      "manifest_hash" => string_field(attrs, "manifest_hash")
    }
  end

  defp mark_device_pending_acted(user_id, registration_id) do
    acted_at = DateTime.utc_now()

    Repo.update_all(
      from(n in Notification,
        where:
          n.recipient_kind == "user" and n.recipient_id == ^to_string(user_id) and
            n.type == "device.pending_approval" and
            n.dedupe_key == ^"device.pending_approval:#{registration_id}" and is_nil(n.acted_at)
      ),
      set: [acted_at: acted_at]
    )

    :ok
  end

  defp mark_plugin_consent_required_acted(event) do
    acted_at = DateTime.utc_now()

    Repo.update_all(
      from(n in Notification,
        where:
          n.recipient_kind == "user" and n.recipient_id == ^to_string(event.user_id) and
            n.type == "plugin.consent_required" and
            n.dedupe_key ==
              ^"plugin.consent_required:#{event.application_id}:#{event.bundle_hash}:#{event.user_id}" and
            is_nil(n.acted_at)
      ),
      set: [acted_at: acted_at]
    )

    :ok
  end

  defp user_actor(nil, nil), do: system_actor()

  defp user_actor(user_id, device_id) do
    %{
      "user_id" => user_id,
      "device_id" => device_id,
      "session_id" => nil,
      "principal_kind" => "user",
      "principal_id" => user_id
    }
  end

  defp system_actor do
    %{
      "user_id" => nil,
      "device_id" => nil,
      "session_id" => nil,
      "principal_kind" => "system",
      "principal_id" => nil
    }
  end

  defp notification_topic(%Notification{recipient_kind: "user", recipient_id: id}),
    do: user_topic(id)

  defp notification_topic(%Notification{recipient_kind: "device", recipient_id: id}),
    do: device_topic(id)

  defp notification_topic(%Notification{
         recipient_kind: "pending_registration",
         recipient_id: id
       }),
       do: pending_registration_topic(id)

  defp notification_topic(%Notification{recipient_kind: "workspace_role", recipient_id: id}),
    do: workspace_topic(id)

  defp user_topic(user_id), do: "security:user:#{user_id}"
  defp device_topic(device_id), do: "security:device:#{device_id}"

  defp pending_registration_topic(registration_id),
    do: "security:pending_registration:#{registration_id}"

  defp workspace_topic(workspace_id), do: "security:workspace:#{workspace_id}"

  defp normalize_audit_attrs(attrs) do
    attrs
    |> Enum.map(fn {key, value} -> {normalize_key(key), stringify_nested_keys(value)} end)
    |> Map.new()
  end

  defp normalize_notification_attrs(attrs) do
    attrs
    |> Enum.map(fn {key, value} -> {normalize_key(key), stringify_nested_keys(value)} end)
    |> Map.new()
    |> Map.update(:recipient_id, nil, &to_string/1)
  end

  defp stringify_nested_keys(%DateTime{} = value), do: value
  defp stringify_nested_keys(%NaiveDateTime{} = value), do: value

  defp stringify_nested_keys(%{} = value) do
    value
    |> Enum.map(fn {key, nested} -> {to_string(key), stringify_nested_keys(nested)} end)
    |> Map.new()
  end

  defp stringify_nested_keys(value) when is_list(value),
    do: Enum.map(value, &stringify_nested_keys/1)

  defp stringify_nested_keys(value), do: value

  defp normalize_key(key) when is_atom(key), do: key
  defp normalize_key(key) when is_binary(key), do: String.to_existing_atom(key)

  defp attrs_to_map(%_{} = struct), do: Map.from_struct(struct)
  defp attrs_to_map(%{} = attrs), do: attrs

  defp reason_code(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp reason_code(reason) when is_binary(reason), do: reason
  defp reason_code(_reason), do: "plugin_bundle_rejected"

  defp canonical_source_host(nil), do: nil

  defp canonical_source_host(source_url) when is_binary(source_url) do
    case URI.parse(source_url) do
      %URI{host: host} when is_binary(host) -> String.downcase(host)
      _ -> nil
    end
  end
end
