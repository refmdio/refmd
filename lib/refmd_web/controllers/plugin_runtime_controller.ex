defmodule RefMDWeb.PluginRuntimeController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Plugins
  alias RefMD.Plugins.SandboxDocumentRenderer
  alias RefMD.Security
  alias RefMD.Workspaces
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:read"]
       when action in [:index, :show, :create_sandbox_document, :audit]

  operation(:index,
    summary: "List runnable plugin runtime descriptors",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin runtime descriptors", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    if is_binary(device_id) do
      descriptors =
        workspace_id
        |> Plugins.list_runtime_descriptors(user_id, device_id)
        |> Enum.map(&format_runtime_descriptor/1)

      json(conn, %{applications: descriptors})
    else
      conn |> put_status(:forbidden) |> json(%{error: "device_session_required"})
    end
  end

  operation(:create_sandbox_document,
    summary: "Create a single-use plugin sandbox document session",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      application_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Sandbox document request", "application/json",
       %OpenApiSpex.Schema{
         type: :object,
         properties: %{
           state_head_hash: %OpenApiSpex.Schema{type: :string, minLength: 1},
           consent_head_hash: %OpenApiSpex.Schema{type: :string, minLength: 1},
           capability_grant_id: %OpenApiSpex.Schema{type: :string, minLength: 1},
           wasm_browser_target: %OpenApiSpex.Schema{type: :string, minLength: 1},
           frame_scope: %OpenApiSpex.Schema{type: :string, enum: ["primary", "secondary"]}
         },
         required: [:state_head_hash, :consent_head_hash, :capability_grant_id]
       }},
    responses: [
      ok: {"Sandbox document session", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create_sandbox_document(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_sandbox_document(conn, params) do
    user_id = conn.assigns.current_user_id
    current_session = conn.assigns.current_session
    device_id = current_session.device_id

    with {:ok, state_head_hash} <-
           non_empty(params["state_head_hash"], "state_head_hash_required"),
         {:ok, consent_head_hash} <-
           non_empty(params["consent_head_hash"], "consent_head_hash_required"),
         {:ok, capability_grant_id} <-
           non_empty(params["capability_grant_id"], "capability_grant_id_required"),
         true <- is_binary(device_id),
         {:ok, payload} <-
           Plugins.runtime_bundle_with_pins(
             params["application_id"],
             params["workspace_id"],
             user_id,
             device_id,
             state_head_hash,
             consent_head_hash
           ),
         :ok <- validate_capability_grant(capability_grant_id, payload),
         {:ok, sandbox_variant_attrs} <-
           sandbox_document_variant_session_attrs(params, payload) do
      session =
        %{
          workspace_id: params["workspace_id"],
          package_id: payload.package_id,
          application_id: params["application_id"],
          activation_id: payload.activation_id,
          owner_scope_kind: payload.owner_scope_kind,
          user_id: user_id,
          device_id: device_id,
          auth_session_id: current_session.id,
          bundle_id: payload.bundle_id,
          bundle_hash: payload.bundle_hash,
          manifest_hash: payload.manifest_hash,
          resource_manifest_hash: payload.resource_manifest_hash,
          state_head_hash: state_head_hash,
          consent_head_hash: consent_head_hash,
          consent_epoch: payload.consent_epoch,
          capability_grant_id: payload.capability_grant_id,
          sandbox_document_frame_scope: sandbox_document_frame_scope(params)
        }
        |> Map.merge(sandbox_variant_attrs)
        |> Plugins.create_sandbox_document_session()

      json(conn, format_sandbox_document_session(payload, session))
    else
      false ->
        conn |> put_status(:forbidden) |> json(%{error: "device_session_required"})

      {:error, :application_not_found} ->
        not_found(conn)

      {:error, :not_found} ->
        conn |> put_status(:forbidden) |> json(%{error: "plugin_consent_required"})

      {:error, reason} ->
        error_response(conn, reason)
    end
  end

  @spec show_sandbox_document(Plug.Conn.t(), map()) :: Plug.Conn.t()
  operation(:show_sandbox_document,
    summary: "Load a single-use plugin sandbox document",
    parameters: [
      session_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin sandbox document", "text/html", %OpenApiSpex.Schema{type: :string}},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show_sandbox_document(conn, %{"session_id" => session_id}) do
    user_id = conn.assigns.current_user_id
    current_session = conn.assigns.current_session
    device_id = current_session.device_id

    with true <- is_binary(device_id),
         :ok <- validate_iframe_navigation(conn),
         {:ok, session} <-
           Plugins.consume_sandbox_document_session(session_id, %{
             user_id: user_id,
             device_id: device_id,
             auth_session_id: current_session.id
           }),
         :ok <- authorize_sandbox_workspace_read(user_id, session.workspace_id),
         {:ok, payload} <-
           Plugins.runtime_bundle_with_pins(
             session.application_id,
             session.workspace_id,
             user_id,
             device_id,
             session.state_head_hash,
             session.consent_head_hash
           ),
         :ok <- validate_sandbox_session_binding(session, payload),
         :ok <- validate_capability_grant(session.capability_grant_id, payload),
         {:ok, document} <-
           SandboxDocumentRenderer.render(
             payload,
             session,
             sandbox_document_render_options(session, payload)
           ) do
      :ok = Plugins.mark_sandbox_document_served(session)

      conn
      |> Plug.Conn.delete_resp_header("x-frame-options")
      |> put_resp_header("content-security-policy", document.csp)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("referrer-policy", "no-referrer")
      |> put_resp_content_type("text/html", "utf-8")
      |> send_resp(200, document.html)
    else
      false ->
        conn |> put_status(:forbidden) |> json(%{error: "device_session_required"})

      {:error, :application_not_found} ->
        not_found(conn)

      {:error, :not_found} ->
        conn |> put_status(:forbidden) |> json(%{error: "plugin_consent_required"})

      {:error, reason} ->
        error_response(conn, reason)
    end
  end

  operation(:show,
    summary: "Get pinned plugin runtime bundle",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      application_id: [in: :path, type: :string, required: true],
      state_head_hash: [in: :query, type: :string, required: true],
      consent_head_hash: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin runtime bundle", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, params) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    with {:ok, state_head_hash} <-
           non_empty(params["state_head_hash"], "state_head_hash_required"),
         {:ok, consent_head_hash} <-
           non_empty(params["consent_head_hash"], "consent_head_hash_required"),
         true <- is_binary(device_id),
         {:ok, payload} <-
           Plugins.runtime_bundle_with_pins(
             params["application_id"],
             params["workspace_id"],
             user_id,
             device_id,
             state_head_hash,
             consent_head_hash
           ) do
      json(conn, format_runtime_bundle(payload))
    else
      false ->
        conn |> put_status(:forbidden) |> json(%{error: "device_session_required"})

      {:error, :application_not_found} ->
        not_found(conn)

      {:error, :not_found} ->
        conn |> put_status(:forbidden) |> json(%{error: "plugin_consent_required"})

      {:error, reason} ->
        error_response(conn, reason)
    end
  end

  operation(:removed_bundle_endpoint,
    summary: "Reject removed plugin runtime bundle endpoint",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      application_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      gone: {"Removed endpoint", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec removed_bundle_endpoint(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def removed_bundle_endpoint(conn, _params) do
    conn
    |> put_status(:gone)
    |> json(%{error: "plugin_runtime_bundle_endpoint_removed"})
  end

  operation(:audit,
    summary: "Record a plugin runtime audit event",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Plugin runtime audit event", "application/json", Schemas.PluginRuntimeAuditRequest},
    responses: [
      ok: {"Recorded", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec audit(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def audit(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    with true <- is_binary(device_id),
         true <- runtime_audit_workspace_matches?(params, workspace_id),
         :ok <- Plugins.validate_runtime_audit_event(params, user_id, device_id),
         {:ok, _} <- Security.record_plugin_runtime_event(params, user_id, device_id),
         :ok <- Plugins.apply_runtime_audit_frame_lifecycle(params, user_id, device_id) do
      json(conn, %{ok: true})
    else
      false ->
        conn |> put_status(:forbidden) |> json(%{error: "workspace_mismatch"})

      {:error, :plugin_runtime_audit_type_invalid} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "plugin_runtime_audit_type_invalid"})

      {:error, :plugin_runtime_audit_application_invalid} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "plugin_runtime_audit_application_invalid"})

      {:error, :plugin_runtime_audit_envelope_invalid} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "plugin_runtime_audit_envelope_invalid"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "security_audit_failed", details: inspect(changeset.errors)})
    end
  end

  defp non_empty(value, error) when is_binary(value) do
    if String.trim(value) == "", do: {:error, error}, else: {:ok, value}
  end

  defp non_empty(_value, error), do: {:error, error}

  defp format_runtime_bundle(payload) do
    %{
      plugin_id: payload.plugin_id,
      package_id: payload.package_id,
      bundle_id: payload.bundle_id,
      application_id: payload.application_id,
      activation_id: payload.activation_id,
      owner_scope_kind: payload.owner_scope_kind,
      workspace_id: payload.workspace_id,
      version: payload.version,
      bundle_hash: payload.bundle_hash,
      manifest_hash: payload.manifest_hash,
      main_js_hash: payload.main_js_hash,
      styles_css_hash: payload.styles_css_hash,
      resource_manifest_hash: payload.resource_manifest_hash,
      resource_manifest: payload.resource_manifest,
      permissions_hash: payload.permissions_hash,
      endpoint_hash: payload.endpoint_hash,
      renderer_slots_hash: payload.renderer_slots_hash,
      document_scope_hash: payload.document_scope_hash,
      approval_event_hash: payload.approval_event_hash,
      consent_event_hash: payload.consent_event_hash,
      consent_epoch: payload.consent_epoch,
      state_head_hash: payload.state_head_hash,
      approval_proof: payload.approval_proof,
      consent_proof: payload.consent_proof,
      manifest_json: payload.manifest_json,
      manifest_json_bytes: Base.encode64(payload.manifest_json_bytes),
      main_js: Base.encode64(payload.main_js),
      styles_css: Base.encode64(payload.styles_css),
      resources: Enum.map(payload.resources, &format_runtime_resource/1)
    }
  end

  defp format_sandbox_document_session(payload, session) do
    payload
    |> format_runtime_metadata()
    |> Map.merge(%{
      sandbox_document_url: "/api/plugin-runtime/sandbox-documents/#{session.id}",
      boot_nonce: session.boot_nonce,
      frame_generation: session.frame_generation,
      frame_scope: Atom.to_string(session.sandbox_document_frame_scope),
      capability_grant_id: session.capability_grant_id,
      expires_at_ms: session.expires_at_ms
    })
  end

  defp format_runtime_metadata(payload) do
    %{
      plugin_id: payload.plugin_id,
      package_id: payload.package_id,
      bundle_id: payload.bundle_id,
      application_id: payload.application_id,
      activation_id: payload.activation_id,
      owner_scope_kind: payload.owner_scope_kind,
      workspace_id: payload.workspace_id,
      version: payload.version,
      bundle_hash: payload.bundle_hash,
      manifest_hash: payload.manifest_hash,
      main_js_hash: payload.main_js_hash,
      styles_css_hash: payload.styles_css_hash,
      resource_manifest_hash: payload.resource_manifest_hash,
      resource_manifest: payload.resource_manifest,
      permissions_hash: payload.permissions_hash,
      endpoint_hash: payload.endpoint_hash,
      renderer_slots_hash: payload.renderer_slots_hash,
      document_scope_hash: payload.document_scope_hash,
      approval_event_hash: payload.approval_event_hash,
      consent_event_hash: payload.consent_event_hash,
      consent_epoch: payload.consent_epoch,
      state_head_hash: payload.state_head_hash,
      approval_proof: payload.approval_proof,
      consent_proof: payload.consent_proof,
      manifest_json: payload.manifest_json,
      manifest_json_bytes: Base.encode64(payload.manifest_json_bytes)
    }
  end

  defp format_runtime_resource(resource) do
    %{
      path: resource.path,
      kind: resource.kind,
      media_type: resource.media_type,
      byte_length: resource.byte_length,
      hash: resource.hash,
      bytes: Base.encode64(resource.bytes)
    }
  end

  @spec format_runtime_descriptor(map()) :: map()
  def format_runtime_descriptor(descriptor) do
    %{
      plugin_id: descriptor.plugin_id,
      package_id: descriptor.package_id,
      application_id: descriptor.application_id,
      activation_id: descriptor.activation_id,
      capability_grant_id: descriptor.capability_grant_id,
      owner_scope_kind: descriptor.owner_scope_kind,
      application_scope_kind: descriptor.application_scope_kind,
      workspace_id: descriptor.workspace_id,
      state_head_hash: descriptor.state_head_hash,
      consent_head_hash: descriptor.consent_head_hash,
      consent_epoch: descriptor.consent_epoch,
      version: descriptor.version,
      bundle_hash: descriptor.bundle_hash,
      approval_event_hash: descriptor.approval_event_hash,
      manifest_hash: descriptor.manifest_hash,
      resource_manifest_hash: descriptor.resource_manifest_hash,
      permissions_hash: descriptor.permissions_hash,
      endpoint_hash: descriptor.endpoint_hash,
      renderer_slots_hash: descriptor.renderer_slots_hash,
      document_scope_hash: descriptor.document_scope_hash,
      signer_user_id: descriptor.signer_user_id,
      signer_device_id: descriptor.signer_device_id,
      title: descriptor.title,
      author: descriptor.author,
      permissions: descriptor.permissions,
      document_scope: descriptor.document_scope,
      network_endpoints: descriptor.network_endpoints,
      renderer_slots: descriptor.renderer_slots,
      document_scopes: descriptor.document_scopes,
      high_risk_consents: descriptor.high_risk_consents
    }
  end

  defp runtime_audit_workspace_matches?(%{"workspace_id" => event_workspace_id}, workspace_id),
    do: event_workspace_id == workspace_id

  defp runtime_audit_workspace_matches?(_params, _workspace_id), do: false

  defp sandbox_document_variant_session_attrs(params, payload) do
    wasm_browser_target = params["wasm_browser_target"]

    cond do
      not wasm_resources?(payload) and blank?(wasm_browser_target) ->
        {:ok, %{}}

      not wasm_resources?(payload) ->
        {:error, :plugin_wasm_variant_invalid}

      blank?(wasm_browser_target) ->
        {:error, :plugin_wasm_runtime_disabled}

      not wasm_browser_target_allowed?(wasm_browser_target) ->
        {:error, :plugin_wasm_variant_invalid}

      true ->
        {:ok,
         %{
           sandbox_document_variant: :wasm_capable,
           wasm_browser_target: wasm_browser_target
         }}
    end
  end

  defp sandbox_document_frame_scope(%{"frame_scope" => "secondary"}), do: :secondary
  defp sandbox_document_frame_scope(_params), do: :primary

  defp sandbox_document_render_options(session, payload) do
    wasm_browser_target = Map.get(session, :wasm_browser_target)

    if wasm_resources?(payload) and Map.get(session, :sandbox_document_variant) == :wasm_capable and
         wasm_browser_target_allowed?(wasm_browser_target) do
      [variant: :wasm_capable, browser_target: wasm_browser_target]
    else
      []
    end
  end

  defp wasm_resources?(payload), do: Enum.any?(payload.resources, &(&1.kind == "wasm"))

  defp wasm_browser_target_allowed?(target) when is_binary(target) and target != "" do
    :refmd
    |> Application.get_env(:plugin_wasm_browser_targets, [])
    |> Enum.member?(target)
  end

  defp wasm_browser_target_allowed?(_target), do: false

  defp blank?(value), do: value in [nil, ""]

  defp error_response(conn, reason)
       when reason in [
              :plugin_state_head_pin_required,
              :plugin_consent_head_pin_required,
              "state_head_hash_required",
              "consent_head_hash_required",
              "capability_grant_id_required"
            ] do
    conn |> put_status(:bad_request) |> json(%{error: to_string(reason)})
  end

  defp error_response(conn, reason)
       when reason in [
              :plugin_sandbox_document_session_not_found,
              :plugin_sandbox_document_session_expired,
              :plugin_sandbox_document_session_mismatch,
              :plugin_sandbox_document_capability_grant_mismatch,
              :plugin_sandbox_document_workspace_forbidden,
              :plugin_sandbox_document_fetch_context_invalid
            ] do
    conn |> put_status(:forbidden) |> json(%{error: to_string(reason)})
  end

  defp error_response(conn, reason)
       when reason in [
              :plugin_application_disabled,
              :plugin_activation_disabled,
              :plugin_workspace_policy_denied,
              :plugin_bundle_not_pinned,
              :plugin_consent_not_allowed
            ] do
    conn |> put_status(:forbidden) |> json(%{error: to_string(reason)})
  end

  defp error_response(conn, reason)
       when reason in [
              :plugin_state_rollback,
              :plugin_consent_rollback,
              :plugin_bundle_runtime_hash_mismatch,
              :plugin_bundle_approval_signature_invalid,
              :plugin_bundle_candidate_missing,
              :plugin_wasm_runtime_disabled,
              :plugin_wasm_variant_invalid,
              :plugin_source_encoding_invalid,
              :plugin_script_inline_forbidden,
              :plugin_style_inline_forbidden,
              :plugin_bundle_dependency_forbidden
            ] do
    conn |> put_status(:conflict) |> json(%{error: to_string(reason)})
  end

  defp error_response(conn, _reason),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp not_found(conn), do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp validate_capability_grant(capability_grant_id, payload)
       when is_binary(capability_grant_id) do
    if capability_grant_id == payload.capability_grant_id do
      :ok
    else
      {:error, :plugin_sandbox_document_capability_grant_mismatch}
    end
  end

  defp validate_sandbox_session_binding(session, payload) do
    expected = %{
      package_id: payload.package_id,
      application_id: payload.application_id,
      activation_id: payload.activation_id,
      owner_scope_kind: payload.owner_scope_kind,
      workspace_id: payload.workspace_id,
      bundle_id: payload.bundle_id,
      bundle_hash: payload.bundle_hash,
      manifest_hash: payload.manifest_hash,
      resource_manifest_hash: payload.resource_manifest_hash,
      state_head_hash: payload.state_head_hash,
      consent_head_hash: payload.consent_event_hash,
      consent_epoch: payload.consent_epoch
    }

    if Enum.all?(expected, fn {key, value} -> Map.get(session, key) == value end) do
      :ok
    else
      {:error, :plugin_sandbox_document_session_mismatch}
    end
  end

  defp authorize_sandbox_workspace_read(user_id, workspace_id) do
    case Workspaces.get_member_with_role(workspace_id, user_id) do
      {_member, role} ->
        if Workspaces.permission_granted?(role, "document:read") do
          :ok
        else
          {:error, :plugin_sandbox_document_workspace_forbidden}
        end

      nil ->
        {:error, :plugin_sandbox_document_workspace_forbidden}
    end
  end

  defp validate_iframe_navigation(conn) do
    case validate_fetch_header(conn, "sec-fetch-dest", "iframe") do
      :ok ->
        case validate_fetch_header(conn, "sec-fetch-mode", "navigate") do
          :ok -> validate_fetch_header(conn, "sec-fetch-site", "same-origin")
          error -> error
        end

      error ->
        error
    end
  end

  defp validate_fetch_header(conn, header, expected) do
    case get_req_header(conn, header) do
      [^expected] -> :ok
      _ -> {:error, :plugin_sandbox_document_fetch_context_invalid}
    end
  end
end
