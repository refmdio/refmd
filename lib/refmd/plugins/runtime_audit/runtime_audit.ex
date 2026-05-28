defmodule RefMD.Plugins.RuntimeAudit do
  @moduledoc """
  Validation for plugin runtime audit envelopes.
  """

  import Ecto.Query

  alias RefMD.Plugins.{
    Consent,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginConsentEvent,
    PluginPackage,
    RuntimeDescriptors,
    SandboxDocuments
  }

  alias RefMD.Repo

  @sensitivity_keys MapSet.new([
                      "plaintext_scope_kind",
                      "plaintext_bytes",
                      "egress_bytes",
                      "storage_bytes"
                    ])
  @plaintext_scope_kinds MapSet.new([
                           "none",
                           "selection",
                           "block",
                           "inline",
                           "editor_context",
                           "active_document",
                           "selected_documents",
                           "workspace"
                         ])
  @correlation_keys MapSet.new([
                      "request_id",
                      "capability_id",
                      "execution_context_id",
                      "authority_event_ref"
                    ])
  @plaintext_event_types MapSet.new([
                           "plugin.plaintext_payload.delivered",
                           "plugin.plaintext_payload.denied"
                         ])
  @plaintext_denied_without_context_reasons MapSet.new([
                                              "execution_context_required"
                                            ])
  @network_event_types MapSet.new([
                         "plugin.network.requested",
                         "plugin.network.blocked"
                       ])
  @pre_target_network_reasons MapSet.new([
                                "endpoint_id_invalid",
                                "extension_route_unavailable",
                                "method_invalid",
                                "network_endpoint_unknown",
                                "network_payload_invalid",
                                "network_route_invalid",
                                "network_route_unavailable",
                                "network_url_forbidden",
                                "no_cors_forbidden",
                                "plugin_proxy_forbidden",
                                "network_url_invalid"
                              ])
  @terminal_event_types MapSet.new([
                          "plugin.sandbox.destroyed",
                          "plugin.capability.revoked"
                        ])
  @ui_registration_event_types MapSet.new([
                                 "plugin.ui.registration.accepted",
                                 "plugin.ui.registration.rejected"
                               ])
  @cleanup_event_types MapSet.new([
                         "plugin.ui.registry_entry_disposed",
                         "plugin.ui.iframe.closed_with_live_entries",
                         "plugin.ui.iframe.lifecycle"
                       ])
  @preload_event_types MapSet.new([
                         "plugin.bundle.imported",
                         "plugin.capability.issued",
                         "plugin.capability.denied"
                       ])
  @action_keys [
    "operation",
    "result",
    "reason_code"
  ]
  @network_action_keys @action_keys ++
                         [
                           "endpoint_id",
                           "route",
                           "method",
                           "target_origin",
                           "target_path",
                           "request_bytes",
                           "response_bytes",
                           "credential_handle_used",
                           "proxy_id",
                           "fallback_reason"
                         ]
  @action_results MapSet.new(["allowed", "denied", "failed", "completed"])
  @event_types MapSet.new([
                 "plugin.plaintext_payload.delivered",
                 "plugin.plaintext_payload.denied",
                 "plugin.ui.registration.accepted",
                 "plugin.ui.registration.rejected",
                 "plugin.ui.invocation.accepted",
                 "plugin.ui.invocation.rejected",
                 "plugin.ui.owner_stale_frame_rejected",
                 "plugin.ui.consent_stale_rejected",
                 "plugin.ui.capability_mismatch_rejected",
                 "plugin.ui.registry_entry_disposed",
                 "plugin.ui.iframe.closed_with_live_entries",
                 "plugin.ui.iframe.lifecycle",
                 "plugin.bundle.imported",
                 "plugin.sandbox.loaded",
                 "plugin.sandbox.destroyed",
                 "plugin.runtime.navigation_suspected",
                 "plugin.capability.issued",
                 "plugin.capability.denied",
                 "plugin.capability.revoked",
                 "plugin.network.requested",
                 "plugin.network.blocked",
                 "plugin.credential.used",
                 "plugin.storage.written",
                 "plugin.document_write.requested"
               ])

  @spec validate_event(map()) :: :ok | {:error, atom()}
  def validate_event(attrs) when is_map(attrs), do: validate_event(attrs, nil, nil)

  @spec validate_event(map(), Ecto.UUID.t() | nil, Ecto.UUID.t() | nil) :: :ok | {:error, atom()}
  def validate_event(attrs, user_id, device_id) when is_map(attrs) do
    type = Map.get(attrs, "type")

    with :ok <- validate_type(type),
         application_id when is_binary(application_id) <- Map.get(attrs, "application_id"),
         %PluginApplication{} = application <- Repo.get(PluginApplication, application_id),
         %PluginApplication{} = application <- Repo.preload(application, :package),
         true <- application.package_id == Map.get(attrs, "package_id"),
         %PluginPackage{} = package <- application.package,
         true <- package.owner_scope_kind == Map.get(attrs, "owner_scope_kind"),
         true <- application.workspace_id == Map.get(attrs, "workspace_id"),
         true <- application.plugin_id == Map.get(attrs, "plugin_id"),
         {:ok, bundle} <- validate_bundle_binding(type, application, attrs),
         :ok <- validate_runtime_identity(type, application, bundle, attrs, user_id, device_id),
         :ok <- validate_envelope(attrs, type) do
      :ok
    else
      {:error, reason} ->
        {:error, reason}

      _ ->
        {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  @spec apply_frame_lifecycle(map(), Ecto.UUID.t() | nil, Ecto.UUID.t() | nil) ::
          :ok | {:error, atom()}
  def apply_frame_lifecycle(%{"type" => type} = attrs, user_id, device_id)
      when type in [
             "plugin.sandbox.loaded",
             "plugin.sandbox.destroyed",
             "plugin.capability.revoked"
           ] do
    with application_id when is_binary(application_id) <- Map.get(attrs, "application_id"),
         %PluginApplication{} = application <- Repo.get(PluginApplication, application_id),
         {:ok, bundle} <- validate_bundle_binding(type, application, attrs),
         {:ok, frame_attrs} <-
           runtime_frame_attrs(type, application, bundle, attrs, user_id, device_id) do
      apply_frame_lifecycle_type(type, frame_attrs)
    else
      _ -> {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  def apply_frame_lifecycle(_attrs, _user_id, _device_id), do: :ok

  defp validate_type(type) when is_binary(type) do
    if MapSet.member?(@event_types, type) do
      :ok
    else
      {:error, :plugin_runtime_audit_type_invalid}
    end
  end

  defp validate_type(_type), do: {:error, :plugin_runtime_audit_type_invalid}

  defp validate_bundle_binding(type, application, attrs) do
    cond do
      MapSet.member?(@terminal_event_types, type) ->
        validate_historical_bundle(application, attrs)

      MapSet.member?(@cleanup_event_types, type) ->
        validate_historical_bundle(application, attrs)

      true ->
        validate_current_bundle(application, attrs)
    end
  end

  defp validate_current_bundle(application, attrs) do
    validate_current_bundle(application, attrs, true)
  end

  defp validate_current_bundle(application, attrs, require_enabled?) do
    application = Repo.preload(application, :current_bundle)

    with true <- (not require_enabled? or application.enabled) and is_nil(application.deleted_at),
         %PluginBundle{} = bundle <- application.current_bundle,
         true <- bundle.bundle_hash == Map.get(attrs, "bundle_hash"),
         true <- bundle.manifest_hash == Map.get(attrs, "manifest_hash") do
      {:ok, bundle}
    else
      _ -> {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  defp validate_historical_bundle(application, attrs) do
    case validate_current_bundle(application, attrs, false) do
      {:ok, %PluginBundle{} = bundle} ->
        {:ok, bundle}

      {:error, :plugin_runtime_audit_application_invalid} ->
        case historical_bundle(application, attrs) do
          %PluginBundle{} = bundle -> {:ok, bundle}
          nil -> {:error, :plugin_runtime_audit_application_invalid}
        end
    end
  end

  defp historical_bundle(application, %{
         "bundle_hash" => bundle_hash,
         "manifest_hash" => manifest_hash
       })
       when is_binary(bundle_hash) and is_binary(manifest_hash) do
    application
    |> historical_bundle_query(bundle_hash, manifest_hash)
    |> Repo.one()
  end

  defp historical_bundle(_application, _attrs), do: nil

  defp historical_bundle_query(application, bundle_hash, manifest_hash) do
    from(b in PluginBundle,
      where:
        (b.application_id == ^application.id or
           (is_nil(b.application_id) and b.package_id == ^application.package_id)) and
          (is_nil(b.workspace_id) or b.workspace_id == ^application.workspace_id) and
          b.plugin_id == ^application.plugin_id and
          b.bundle_hash == ^bundle_hash and
          b.manifest_hash == ^manifest_hash,
      limit: 1
    )
  end

  defp validate_runtime_identity(type, application, bundle, attrs, user_id, device_id) do
    with {:ok, frame_attrs} <-
           runtime_frame_attrs(type, application, bundle, attrs, user_id, device_id),
         true <- runtime_frame_valid?(type, frame_attrs, attrs) do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  defp runtime_frame_attrs(type, application, bundle, attrs, user_id, device_id) do
    with activation_id when is_binary(activation_id) <- Map.get(attrs, "activation_id"),
         %PluginActivation{} = activation <- Repo.get(PluginActivation, activation_id),
         true <- activation.application_id == application.id,
         true <- activation.user_id == user_id,
         true <- activation.device_id == device_id or is_nil(activation.device_id),
         :ok <- validate_activation_state(type, activation),
         consent_epoch when is_integer(consent_epoch) <- Map.get(attrs, "consent_epoch"),
         %PluginConsentEvent{} = consent <-
           runtime_consent_event(type, application.id, user_id, device_id, consent_epoch),
         true <- consent.activation_id == activation.id,
         true <- consent.decision == "allow",
         true <- Consent.matches_bundle?(bundle, consent),
         capability_grant_application =
           capability_grant_application(type, application, bundle, attrs),
         capability_grant_id when is_binary(capability_grant_id) <-
           Map.get(attrs, "capability_grant_id"),
         true <-
           capability_grant_id ==
             RuntimeDescriptors.capability_grant_id(
               capability_grant_application,
               bundle,
               activation,
               consent,
               user_id,
               device_id
             ),
         frame_generation when is_integer(frame_generation) <- Map.get(attrs, "frame_generation"),
         true <- frame_generation > 0 do
      {:ok,
       %{
         workspace_id: application.workspace_id,
         package_id: application.package_id,
         application_id: application.id,
         activation_id: activation.id,
         owner_scope_kind: consent.owner_scope_kind,
         user_id: user_id,
         device_id: device_id,
         state_head_hash: capability_grant_application.state_head_hash,
         consent_head_hash: audit_consent_head_hash(attrs, consent.event_hash),
         consent_epoch: consent_epoch,
         capability_grant_id: capability_grant_id,
         frame_generation: frame_generation,
         sandbox_document_frame_scope: audit_frame_scope(attrs)
       }}
    else
      _ -> {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  defp runtime_frame_valid?("plugin.sandbox.loaded", attrs, _event_attrs),
    do: SandboxDocuments.loadable_frame?(attrs)

  defp runtime_frame_valid?(
         "plugin.plaintext_payload.denied",
         attrs,
         %{"action" => %{"reason_code" => "execution_context_required"}}
       ) do
    SandboxDocuments.preload_frame?(attrs)
  end

  defp runtime_frame_valid?(type, attrs, _event_attrs) do
    cond do
      MapSet.member?(@ui_registration_event_types, type) -> primary_loadable_frame?(attrs)
      MapSet.member?(@preload_event_types, type) -> SandboxDocuments.preload_frame?(attrs)
      MapSet.member?(@terminal_event_types, type) -> SandboxDocuments.terminal_frame?(attrs, type)
      MapSet.member?(@cleanup_event_types, type) -> SandboxDocuments.cleanup_frame?(attrs)
      true -> SandboxDocuments.current_frame?(attrs)
    end
  end

  defp primary_loadable_frame?(%{sandbox_document_frame_scope: :primary} = attrs),
    do: SandboxDocuments.loadable_frame?(attrs)

  defp primary_loadable_frame?(_attrs), do: false

  defp audit_frame_scope(%{"frame_scope" => "secondary"}), do: :secondary
  defp audit_frame_scope(_attrs), do: :primary

  defp apply_frame_lifecycle_type("plugin.sandbox.loaded", attrs) do
    if SandboxDocuments.activate_frame?(attrs) do
      :ok
    else
      {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  defp apply_frame_lifecycle_type(terminal_type, attrs) do
    if SandboxDocuments.terminate_frame?(attrs, terminal_type) do
      :ok
    else
      {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  defp capability_grant_application(type, application, bundle, attrs) do
    default_state_head_hash =
      if MapSet.member?(@terminal_event_types, type) do
        bundle.approval_event_hash
      else
        application.state_head_hash
      end

    %{application | state_head_hash: audit_state_head_hash(attrs, default_state_head_hash)}
  end

  defp audit_state_head_hash(%{"state_head_hash" => value}, _default)
       when is_binary(value) and value != "",
       do: value

  defp audit_state_head_hash(_attrs, default), do: default

  defp audit_consent_head_hash(%{"consent_head_hash" => value}, _default)
       when is_binary(value) and value != "",
       do: value

  defp audit_consent_head_hash(_attrs, default), do: default

  defp validate_activation_state(type, %PluginActivation{} = activation) do
    cond do
      MapSet.member?(@terminal_event_types, type) or MapSet.member?(@cleanup_event_types, type) ->
        :ok

      is_nil(activation.deleted_at) and activation.enabled ->
        :ok

      true ->
        {:error, :plugin_runtime_audit_application_invalid}
    end
  end

  defp runtime_consent_event(type, application_id, user_id, device_id, consent_epoch) do
    query =
      from(c in PluginConsentEvent,
        where:
          c.application_id == ^application_id and c.user_id == ^user_id and
            c.device_id == ^device_id and c.consent_epoch == ^consent_epoch,
        order_by: [desc: c.created_at],
        limit: 1
      )

    event = Repo.one(query)

    if MapSet.member?(@terminal_event_types, type) or MapSet.member?(@cleanup_event_types, type),
      do: event,
      else: current_runtime_consent_event(event, application_id, user_id, device_id)
  end

  defp current_runtime_consent_event(
         %PluginConsentEvent{} = consent,
         application_id,
         user_id,
         device_id
       ) do
    latest = Consent.latest_event(application_id, user_id, device_id)
    if latest && latest.id == consent.id, do: consent
  end

  defp current_runtime_consent_event(_event, _application_id, _user_id, _device_id), do: nil

  defp validate_envelope(attrs, type) do
    sensitivity = Map.get(attrs, "sensitivity")
    correlation = Map.get(attrs, "correlation")

    with :ok <- validate_action(attrs, type),
         :ok <- validate_sensitivity(sensitivity),
         :ok <- validate_correlation(correlation) do
      validate_event_metadata(attrs, sensitivity, correlation)
    end
  end

  defp validate_action(%{"action" => action}, type) when is_map(action) do
    allowed_keys = action_keys(type)

    with true <- Enum.all?(Map.keys(action), &(&1 in allowed_keys)),
         operation when is_binary(operation) <- Map.get(action, "operation"),
         true <- non_empty_string?(operation),
         result when is_binary(result) <- Map.get(action, "result"),
         true <- MapSet.member?(@action_results, result),
         :ok <- validate_reason_code(action) do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_action(_attrs, _type), do: {:error, :plugin_runtime_audit_envelope_invalid}

  defp action_keys(type) do
    if MapSet.member?(@network_event_types, type) do
      @network_action_keys
    else
      @action_keys
    end
  end

  defp validate_reason_code(action) do
    case Map.get(action, "reason_code") do
      nil -> :ok
      value when is_binary(value) -> :ok
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_sensitivity(nil), do: :ok

  defp validate_sensitivity(sensitivity) when is_map(sensitivity) do
    keys = sensitivity |> Map.keys() |> MapSet.new()

    with true <- MapSet.equal?(keys, @sensitivity_keys),
         scope_kind when is_binary(scope_kind) <- Map.get(sensitivity, "plaintext_scope_kind"),
         true <- MapSet.member?(@plaintext_scope_kinds, scope_kind),
         true <- non_negative_integer?(Map.get(sensitivity, "plaintext_bytes")),
         true <- non_negative_integer?(Map.get(sensitivity, "egress_bytes")),
         true <- non_negative_integer?(Map.get(sensitivity, "storage_bytes")) do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_sensitivity(_sensitivity), do: {:error, :plugin_runtime_audit_envelope_invalid}

  defp validate_correlation(nil), do: :ok

  defp validate_correlation(correlation) when is_map(correlation) do
    keys = correlation |> Map.keys() |> MapSet.new()

    if MapSet.equal?(keys, @correlation_keys) and
         Enum.all?(correlation, fn {_key, value} -> is_nil(value) or is_binary(value) end) do
      :ok
    else
      {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_correlation(_correlation), do: {:error, :plugin_runtime_audit_envelope_invalid}

  defp validate_event_metadata(%{"type" => type} = attrs, sensitivity, correlation) do
    cond do
      MapSet.member?(@plaintext_event_types, type) ->
        validate_plaintext_metadata(attrs, sensitivity, correlation)

      MapSet.member?(@network_event_types, type) ->
        validate_network_metadata(attrs)

      true ->
        :ok
    end
  end

  defp validate_event_metadata(_attrs, _sensitivity, _correlation), do: :ok

  defp validate_plaintext_metadata(
         %{"type" => "plugin.plaintext_payload.denied"} = attrs,
         sensitivity,
         correlation
       )
       when is_map(sensitivity) and is_map(correlation) do
    reason_code = get_in(attrs, ["action", "reason_code"])

    if MapSet.member?(@plaintext_denied_without_context_reasons, reason_code) do
      validate_plaintext_denied_without_context_metadata(attrs, sensitivity, correlation)
    else
      validate_plaintext_metadata_with_context(attrs, sensitivity, correlation)
    end
  end

  defp validate_plaintext_metadata(attrs, sensitivity, correlation)
       when is_map(sensitivity) and is_map(correlation) do
    validate_plaintext_metadata_with_context(attrs, sensitivity, correlation)
  end

  defp validate_plaintext_metadata(_attrs, _sensitivity, _correlation),
    do: {:error, :plugin_runtime_audit_envelope_invalid}

  defp validate_plaintext_metadata_with_context(attrs, sensitivity, correlation) do
    with scope_kind when is_binary(scope_kind) <- Map.get(sensitivity, "plaintext_scope_kind"),
         false <- scope_kind == "none",
         true <- non_negative_integer?(Map.get(sensitivity, "plaintext_bytes")),
         execution_context_id when is_binary(execution_context_id) <-
           Map.get(correlation, "execution_context_id"),
         true <- String.trim(execution_context_id) != "",
         request_id when is_binary(request_id) <- Map.get(correlation, "request_id"),
         true <- String.trim(request_id) != "",
         capability_id when is_binary(capability_id) <- Map.get(correlation, "capability_id"),
         true <- String.trim(capability_id) != "",
         payload_kind when is_binary(payload_kind) <- Map.get(attrs, "payloadKind"),
         true <- String.trim(payload_kind) != "",
         context_kind when is_binary(context_kind) <- Map.get(attrs, "contextKind"),
         true <- String.trim(context_kind) != "" do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_plaintext_denied_without_context_metadata(attrs, sensitivity, correlation) do
    with scope_kind when is_binary(scope_kind) <- Map.get(sensitivity, "plaintext_scope_kind"),
         false <- scope_kind == "none",
         true <- non_negative_integer?(Map.get(sensitivity, "plaintext_bytes")),
         request_id when is_binary(request_id) <- Map.get(correlation, "request_id"),
         true <- String.trim(request_id) != "",
         capability_id when is_binary(capability_id) <- Map.get(correlation, "capability_id"),
         true <- String.trim(capability_id) != "",
         payload_kind when is_binary(payload_kind) <- Map.get(attrs, "payloadKind"),
         true <- String.trim(payload_kind) != "" do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_network_metadata(%{"action" => action, "type" => type}) when is_map(action) do
    with endpoint_id when is_binary(endpoint_id) <- Map.get(action, "endpoint_id"),
         true <- non_empty_string?(endpoint_id),
         route when is_binary(route) <- Map.get(action, "route"),
         true <- non_empty_string?(route),
         method when is_binary(method) <- Map.get(action, "method"),
         true <- non_empty_string?(method),
         :ok <- validate_network_target_metadata(type, action),
         true <- non_negative_integer?(Map.get(action, "request_bytes")),
         :ok <- validate_network_response_bytes(type, action),
         true <- is_boolean(Map.get(action, "credential_handle_used")),
         :ok <- validate_network_proxy_id(type, action),
         :ok <- validate_network_fallback_reason(action) do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_network_metadata(_attrs), do: {:error, :plugin_runtime_audit_envelope_invalid}

  defp validate_network_target_metadata("plugin.network.blocked", action) do
    if MapSet.member?(@pre_target_network_reasons, Map.get(action, "reason_code")) do
      validate_optional_network_target_metadata(action)
    else
      validate_required_network_target_metadata(action)
    end
  end

  defp validate_network_target_metadata(_type, action) do
    validate_required_network_target_metadata(action)
  end

  defp validate_optional_network_target_metadata(action) do
    case {Map.get(action, "target_origin"), Map.get(action, "target_path")} do
      {nil, nil} -> :ok
      {_target_origin, _target_path} -> validate_required_network_target_metadata(action)
    end
  end

  defp validate_required_network_target_metadata(action) do
    with target_origin when is_binary(target_origin) <- Map.get(action, "target_origin"),
         true <- canonical_origin?(target_origin),
         target_path when is_binary(target_path) <- Map.get(action, "target_path"),
         true <- canonical_path?(target_path) do
      :ok
    else
      _ -> {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_network_response_bytes("plugin.network.blocked", action) do
    validate_required_non_negative_integer(Map.get(action, "response_bytes"))
  end

  defp validate_network_response_bytes(
         "plugin.network.requested",
         %{"result" => "completed"} = action
       ) do
    validate_required_non_negative_integer(Map.get(action, "response_bytes"))
  end

  defp validate_network_response_bytes("plugin.network.requested", action) do
    case Map.get(action, "response_bytes") do
      nil -> :ok
      value -> validate_required_non_negative_integer(value)
    end
  end

  defp validate_network_response_bytes(_type, _action),
    do: {:error, :plugin_runtime_audit_envelope_invalid}

  defp validate_required_non_negative_integer(value) do
    if non_negative_integer?(value) do
      :ok
    else
      {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_network_proxy_id("plugin.network.blocked", %{"route" => "proxy"} = action) do
    case Map.get(action, "proxy_id") do
      proxy_id when is_binary(proxy_id) ->
        if non_empty_string?(proxy_id) do
          :ok
        else
          {:error, :plugin_runtime_audit_envelope_invalid}
        end

      _ ->
        if MapSet.member?(@pre_target_network_reasons, Map.get(action, "reason_code")) do
          :ok
        else
          {:error, :plugin_runtime_audit_envelope_invalid}
        end
    end
  end

  defp validate_network_proxy_id(_type, %{"route" => "proxy"} = action) do
    case Map.get(action, "proxy_id") do
      proxy_id when is_binary(proxy_id) ->
        if non_empty_string?(proxy_id) do
          :ok
        else
          {:error, :plugin_runtime_audit_envelope_invalid}
        end

      _ ->
        {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp validate_network_proxy_id(_type, _action), do: :ok

  defp validate_network_fallback_reason(action) do
    case Map.get(action, "fallback_reason") do
      nil ->
        :ok

      reason when is_binary(reason) ->
        if non_empty_string?(reason) do
          :ok
        else
          {:error, :plugin_runtime_audit_envelope_invalid}
        end

      _ ->
        {:error, :plugin_runtime_audit_envelope_invalid}
    end
  end

  defp non_negative_integer?(value), do: is_integer(value) and value >= 0

  defp non_empty_string?(value), do: String.trim(value) != ""

  defp canonical_origin?(origin) when is_binary(origin) do
    case URI.parse(origin) do
      %URI{scheme: "https", host: host, path: nil, query: nil, fragment: nil}
      when is_binary(host) ->
        non_empty_string?(host)

      %URI{scheme: "https", host: host, path: "", query: nil, fragment: nil}
      when is_binary(host) ->
        non_empty_string?(host)

      _ ->
        false
    end
  end

  defp canonical_path?(path) when is_binary(path) do
    String.starts_with?(path, "/") and non_empty_string?(path) and
      not String.contains?(path, "?")
  end
end
