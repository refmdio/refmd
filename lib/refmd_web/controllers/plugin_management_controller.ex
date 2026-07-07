defmodule RefMDWeb.PluginManagementController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Plugins
  alias RefMD.Plugins.PluginActivation
  alias RefMD.Plugins.PluginBundleCandidate
  alias RefMD.Plugins.PluginPackage
  alias RefMD.Plugins.Signing
  alias RefMD.Repo
  alias RefMD.Workspaces
  alias RefMDWeb.PluginRuntimeController
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:read"]
       when action in [
              :consent_required,
              :append_consent,
              :index_plugins,
              :index_workspace_packages,
              :apply_plugin
            ]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:admin"]
       when action in [
              :create_candidate,
              :create_remote_candidate,
              :create_local_candidate,
              :update_plugin,
              :delete_plugin
            ]

  operation(:consent_required,
    summary: "List plugin applications requiring member consent",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin consent-required descriptors", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def consent_required(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    if is_binary(device_id) do
      descriptors =
        workspace_id
        |> Plugins.list_consent_required_descriptors(user_id, device_id)
        |> Enum.map(&format_descriptor/1)

      json(conn, %{applications: descriptors})
    else
      conn |> put_status(:forbidden) |> json(%{error: "device_session_required"})
    end
  end

  operation(:index_plugins,
    summary: "List installed plugins",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin applications", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def index_plugins(conn, %{"workspace_id" => workspace_id}) do
    plugins =
      workspace_id
      |> Plugins.list_applications()
      |> Enum.map(&format_application/1)

    json(conn, %{plugins: plugins})
  end

  operation(:apply_plugin,
    summary: "Apply a plugin package to a workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Plugin application", "application/json", Schemas.PluginApplicationApplyRequest},
    responses: [
      ok: {"Applied plugin application", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def apply_plugin(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    with {:ok, package_id} <- non_empty(params["package_id"], :plugin_package_not_found),
         {:ok, package} <- fetch_package(package_id),
         :ok <- authorize_package_application(conn, package),
         true <- is_binary(device_id),
         {:ok, %{application: application, activation: activation}} <-
           Plugins.apply_package_to_workspace(workspace_id, package_id, user_id, device_id) do
      json(conn, %{
        application: format_application(application),
        activation: format_activation(activation)
      })
    else
      false -> conn |> put_status(:forbidden) |> json(%{error: "device_session_required"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  operation(:index_activations,
    summary: "List current user plugin activations",
    responses: [
      ok: {"Plugin activations", "application/json", Schemas.OkResponse}
    ]
  )

  def index_activations(conn, _params) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    activations =
      user_id
      |> Plugins.list_activations(device_id)
      |> Enum.map(&format_activation/1)

    json(conn, %{activations: activations})
  end

  operation(:update_activation,
    summary: "Update current user plugin activation",
    parameters: [
      activation_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Plugin activation update", "application/json", Schemas.PluginActivationUpdateRequest},
    responses: [
      ok: {"Updated plugin activation", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update_activation(conn, %{"activation_id" => activation_id} = params) do
    with %PluginActivation{} = activation <- Plugins.get_active_activation(activation_id),
         :ok <- authorize_activation_update(conn, activation),
         {:ok, updated} <-
           Plugins.update_activation(activation, activation_update_attrs(params),
             actor_device_id: conn.assigns.current_session.device_id
           ) do
      json(conn, %{activation: format_activation(updated)})
    else
      nil -> not_found(conn)
      {:error, :not_found} -> not_found(conn)
      {:error, :plugin_activation_forbidden} -> error_response(conn, :plugin_activation_forbidden)
      {:error, reason} -> error_response(conn, reason)
    end
  end

  operation(:delete_activation,
    summary: "Delete current user plugin activation",
    parameters: [
      activation_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Deleted plugin activation", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete_activation(conn, %{"activation_id" => activation_id}) do
    with %PluginActivation{} = activation <- Plugins.get_active_activation(activation_id),
         :ok <- authorize_activation_update(conn, activation),
         {:ok, deleted} <-
           Plugins.delete_activation(activation,
             actor_device_id: conn.assigns.current_session.device_id
           ) do
      json(conn, %{activation: format_activation(deleted)})
    else
      nil -> not_found(conn)
      {:error, :not_found} -> not_found(conn)
      {:error, :plugin_activation_forbidden} -> error_response(conn, :plugin_activation_forbidden)
      {:error, reason} -> error_response(conn, reason)
    end
  end

  operation(:index_user_packages,
    summary: "List user-owned plugin packages",
    responses: [
      ok: {"Plugin packages", "application/json", Schemas.OkResponse}
    ]
  )

  def index_user_packages(conn, _params) do
    packages =
      conn.assigns.current_user_id
      |> Plugins.list_user_packages()
      |> Enum.map(&format_package/1)

    json(conn, %{packages: packages})
  end

  operation(:index_workspace_packages,
    summary: "List workspace-owned plugin packages",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin packages", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def index_workspace_packages(conn, %{"workspace_id" => workspace_id}) do
    packages =
      workspace_id
      |> Plugins.list_workspace_packages()
      |> Enum.map(&format_package/1)

    json(conn, %{packages: packages})
  end

  operation(:create_candidate,
    summary: "Create a plugin bundle candidate",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_candidate(conn, %{"source_kind" => "remote_https_url"} = params),
    do: create_remote_candidate(conn, params)

  def create_candidate(conn, %{"source_kind" => "local_upload"} = params),
    do: create_local_candidate(conn, params)

  def create_candidate(conn, %{"source_url" => source_url} = params) when is_binary(source_url),
    do: create_remote_candidate(conn, params)

  def create_candidate(conn, %{"archive_base64" => archive_base64} = params)
      when is_binary(archive_base64),
      do: create_local_candidate(conn, params)

  def create_candidate(conn, _params),
    do: conn |> put_status(:bad_request) |> json(%{error: "source_kind_required"})

  operation(:create_user_candidate,
    summary: "Create a user-owned plugin package candidate",
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_user_candidate(conn, params) do
    params =
      params
      |> Map.put("owner_scope_kind", "user")
      |> Map.delete("workspace_id")

    create_candidate(conn, params)
  end

  operation(:create_manifest_routed_candidate,
    summary: "Create a plugin package candidate through the manifest-routed add flow",
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_manifest_routed_candidate(conn, %{"source_kind" => "remote_https_url"} = params),
    do: create_manifest_routed_remote_candidate(conn, params)

  def create_manifest_routed_candidate(conn, %{"source_kind" => "local_upload"} = params),
    do: create_manifest_routed_local_candidate(conn, params)

  def create_manifest_routed_candidate(conn, %{"source_url" => source_url} = params)
      when is_binary(source_url),
      do: create_manifest_routed_remote_candidate(conn, params)

  def create_manifest_routed_candidate(conn, %{"archive_base64" => archive_base64} = params)
      when is_binary(archive_base64),
      do: create_manifest_routed_local_candidate(conn, params)

  def create_manifest_routed_candidate(conn, _params),
    do: conn |> put_status(:bad_request) |> json(%{error: "source_kind_required"})

  defp create_manifest_routed_remote_candidate(conn, %{"source_url" => source_url} = params)
       when is_binary(source_url) do
    with {:ok, attrs} <- manifest_routed_candidate_attrs(conn, params),
         {:ok, candidate} <-
           Plugins.create_scope_authorized_remote_bundle_candidate(
             source_url,
             attrs,
             &authorize_manifest_routed_candidate(conn, &1)
           ) do
      json(conn, %{candidate: format_candidate(conn, candidate)})
    else
      {:error, reason} -> error_response(conn, reason)
    end
  end

  defp create_manifest_routed_remote_candidate(conn, _params),
    do: conn |> put_status(:bad_request) |> json(%{error: "source_url_required"})

  defp create_manifest_routed_local_candidate(
         conn,
         %{"archive_base64" => archive_base64} = params
       )
       when is_binary(archive_base64) do
    with {:ok, attrs} <- manifest_routed_candidate_attrs(conn, params),
         {:ok, archive_bytes} <- Base.decode64(archive_base64),
         {:ok, archive_path} <- write_upload_archive(archive_bytes) do
      try do
        case Plugins.create_scope_authorized_local_bundle_candidate(
               archive_path,
               attrs,
               &authorize_manifest_routed_candidate(conn, &1)
             ) do
          {:ok, candidate} -> json(conn, %{candidate: format_candidate(conn, candidate)})
          {:error, reason} -> error_response(conn, reason)
        end
      after
        File.rm(archive_path)
      end
    else
      :error -> conn |> put_status(:bad_request) |> json(%{error: "invalid_archive_base64"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  defp create_manifest_routed_local_candidate(conn, _params),
    do: conn |> put_status(:bad_request) |> json(%{error: "archive_base64_required"})

  operation(:create_remote_candidate,
    summary: "Create a remote plugin bundle candidate",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_remote_candidate(conn, %{"source_url" => source_url} = params)
      when is_binary(source_url) do
    with {:ok, attrs} <- candidate_attrs(conn, params),
         {:ok, candidate} <- Plugins.create_remote_bundle_candidate(source_url, attrs) do
      json(conn, %{candidate: format_candidate(conn, candidate)})
    else
      {:error, reason} -> error_response(conn, reason)
    end
  end

  def create_remote_candidate(conn, _params),
    do: conn |> put_status(:bad_request) |> json(%{error: "source_url_required"})

  operation(:create_local_candidate,
    summary: "Create a local plugin bundle candidate",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_local_candidate(conn, %{"archive_base64" => archive_base64} = params)
      when is_binary(archive_base64) do
    with {:ok, attrs} <- candidate_attrs(conn, params),
         {:ok, archive_bytes} <- Base.decode64(archive_base64),
         {:ok, archive_path} <- write_upload_archive(archive_bytes) do
      try do
        case Plugins.create_local_bundle_candidate(archive_path, attrs) do
          {:ok, candidate} -> json(conn, %{candidate: format_candidate(conn, candidate)})
          {:error, reason} -> error_response(conn, reason)
        end
      after
        File.rm(archive_path)
      end
    else
      :error -> conn |> put_status(:bad_request) |> json(%{error: "invalid_archive_base64"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  def create_local_candidate(conn, _params),
    do: conn |> put_status(:bad_request) |> json(%{error: "archive_base64_required"})

  operation(:show_candidate,
    summary: "Show a plugin bundle candidate approval summary",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      candidate_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show_candidate(conn, params) do
    case fetch_candidate(params) do
      {:ok, candidate} -> json(conn, %{candidate: format_candidate(conn, candidate)})
      nil -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      false -> conn |> put_status(:forbidden) |> json(%{error: "candidate_mismatch"})
    end
  end

  operation(:promote_candidate,
    summary: "Promote an approved plugin bundle candidate",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      candidate_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin package", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def promote_candidate(conn, params) do
    with {:ok, %PluginBundleCandidate{} = candidate} <- fetch_candidate(params),
         {:ok, package} <-
           Plugins.promote_bundle_candidate(candidate, approval_attrs(conn, params)) do
      json(conn, promote_response(conn, candidate, package, params))
    else
      nil -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      false -> conn |> put_status(:forbidden) |> json(%{error: "candidate_mismatch"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  operation(:show_candidate_resource,
    summary: "Show a plugin bundle candidate approval summary",
    parameters: [
      candidate_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show_candidate_resource(conn, params) do
    case fetch_owned_candidate(conn, params) do
      {:ok, candidate} -> json(conn, %{candidate: format_candidate(conn, candidate)})
      nil -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      false -> conn |> put_status(:forbidden) |> json(%{error: "candidate_mismatch"})
    end
  end

  operation(:promote_candidate_resource,
    summary: "Promote an approved plugin bundle candidate",
    parameters: [
      candidate_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin package", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def promote_candidate_resource(conn, params) do
    with {:ok, %PluginBundleCandidate{} = candidate} <- fetch_owned_candidate(conn, params),
         {:ok, package} <-
           Plugins.promote_bundle_candidate(candidate, approval_attrs(conn, params)) do
      json(conn, promote_response(conn, candidate, package, params))
    else
      nil -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      false -> conn |> put_status(:forbidden) |> json(%{error: "candidate_mismatch"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  operation(:show_user_candidate,
    summary: "Show a user-owned plugin package candidate approval summary",
    parameters: [
      candidate_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin bundle candidate", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show_user_candidate(conn, params) do
    case fetch_user_candidate(conn, params) do
      {:ok, candidate} -> json(conn, %{candidate: format_candidate(conn, candidate)})
      nil -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      false -> conn |> put_status(:forbidden) |> json(%{error: "candidate_mismatch"})
    end
  end

  operation(:promote_user_candidate,
    summary: "Promote an approved user-owned plugin package candidate",
    parameters: [
      candidate_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Plugin package", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def promote_user_candidate(conn, params) do
    with {:ok, %PluginBundleCandidate{} = candidate} <- fetch_user_candidate(conn, params),
         {:ok, package} <-
           Plugins.promote_bundle_candidate(candidate, approval_attrs(conn, params)) do
      json(conn, %{package: format_package(package)})
    else
      nil -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      false -> conn |> put_status(:forbidden) |> json(%{error: "candidate_mismatch"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  operation(:update_plugin,
    summary: "Update an installed plugin",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      application_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Plugin application update", "application/json", Schemas.PluginApplicationUpdateRequest},
    responses: [
      ok: {"Updated plugin application", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update_plugin(
        conn,
        %{"workspace_id" => workspace_id, "application_id" => application_id} = params
      ) do
    case application_in_workspace(application_id, workspace_id) do
      nil ->
        not_found(conn)

      application ->
        case Plugins.update_application(application, plugin_update_attrs(params)) do
          {:ok, updated} -> json(conn, %{plugin: format_application(updated)})
          {:error, reason} -> error_response(conn, reason)
        end
    end
  end

  operation(:delete_plugin,
    summary: "Uninstall a plugin",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      application_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Deleted plugin application", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete_plugin(conn, %{"workspace_id" => workspace_id, "application_id" => application_id}) do
    case application_in_workspace(application_id, workspace_id) do
      nil ->
        not_found(conn)

      application ->
        case Plugins.delete_application(application) do
          {:ok, deleted} -> json(conn, %{plugin: format_application(deleted)})
          {:error, reason} -> error_response(conn, reason)
        end
    end
  end

  defp application_in_workspace(application_id, workspace_id) do
    case Plugins.get_application(application_id) do
      %{workspace_id: ^workspace_id, deleted_at: nil} = application -> application
      _ -> nil
    end
  end

  operation(:append_consent,
    summary: "Append a plugin consent event",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      application_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Plugin consent event", "application/json", Schemas.PluginConsentEventRequest},
    responses: [
      ok: {"Plugin consent event", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Pinned state mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def append_consent(conn, params) do
    attrs = consent_attrs(conn, params)

    with true <- attrs.workspace_id == params["workspace_id"],
         true <- attrs.application_id == params["application_id"],
         {:ok, consent} <- Plugins.append_consent_event(attrs) do
      json(conn, %{
        consent_event: %{
          event_hash: consent.event_hash,
          decision: consent.decision,
          consent_epoch: consent.consent_epoch
        }
      })
    else
      false -> conn |> put_status(:forbidden) |> json(%{error: "consent_mismatch"})
      {:error, reason} -> error_response(conn, reason)
    end
  end

  defp candidate_attrs(conn, params) do
    workspace_id = params["workspace_id"]
    owner_scope_kind = params["owner_scope_kind"] || params["ownerScopeKind"] || "workspace"

    if is_binary(workspace_id) and owner_scope_kind == "user" do
      {:error, :plugin_package_scope_unsupported}
    else
      {:ok,
       %{
         workspace_id: workspace_id,
         owner_scope_kind: owner_scope_kind,
         created_by_user_id: conn.assigns.current_user_id,
         created_by_device_id: conn.assigns.current_session.device_id
       }}
    end
  end

  defp manifest_routed_candidate_attrs(conn, params) do
    workspace_id = params["workspace_id"]

    cond do
      is_nil(workspace_id) ->
        {:ok,
         %{
           manifest_routed: true,
           routing_workspace_id: workspace_id,
           created_by_user_id: conn.assigns.current_user_id,
           created_by_device_id: conn.assigns.current_session.device_id
         }}

      is_binary(workspace_id) ->
        with :ok <- authorize_manifest_routed_workspace_context(conn, workspace_id) do
          {:ok,
           %{
             manifest_routed: true,
             routing_workspace_id: workspace_id,
             created_by_user_id: conn.assigns.current_user_id,
             created_by_device_id: conn.assigns.current_session.device_id
           }}
        end

      true ->
        {:error, :plugin_package_scope_unsupported}
    end
  end

  defp authorize_manifest_routed_workspace_context(conn, workspace_id) do
    case Workspaces.get_member_with_role(workspace_id, conn.assigns.current_user_id) do
      {_member, role} ->
        if Workspaces.permission_granted?(role, "workspace:admin") do
          :ok
        else
          {:error, :plugin_package_forbidden}
        end

      nil ->
        {:error, :plugin_package_forbidden}
    end
  end

  defp authorize_manifest_routed_candidate(_conn, %{owner_scope_kind: "user"}), do: :ok

  defp authorize_manifest_routed_candidate(conn, %{
         owner_scope_kind: "workspace",
         routing_workspace_id: workspace_id
       })
       when is_binary(workspace_id) do
    authorize_manifest_routed_workspace_context(conn, workspace_id)
  end

  defp authorize_manifest_routed_candidate(_conn, %{owner_scope_kind: "workspace"}),
    do: {:error, :plugin_package_forbidden}

  defp authorize_manifest_routed_candidate(_conn, _candidate_attrs),
    do: {:error, :plugin_package_scope_unsupported}

  defp fetch_package(package_id) do
    case Plugins.get_package(package_id) do
      %PluginPackage{} = package -> {:ok, package}
      nil -> {:error, :plugin_package_not_found}
    end
  end

  defp authorize_package_application(conn, %PluginPackage{owner_scope_kind: "workspace"}) do
    if Workspaces.permission_granted?(conn.assigns.workspace_role, "workspace:admin") do
      :ok
    else
      {:error, :plugin_package_forbidden}
    end
  end

  defp authorize_package_application(_conn, %PluginPackage{}), do: :ok

  defp plugin_update_attrs(params) do
    %{}
    |> maybe_put_param(:enabled, params, "enabled")
    |> maybe_put_param(:workspace_policy_result, params, "workspace_policy_result")
  end

  defp activation_update_attrs(params) do
    %{}
    |> maybe_put_param(:enabled, params, "enabled")
  end

  defp promote_response(conn, candidate, package, params) do
    response = %{package: format_package(package)}

    case maybe_ensure_personal_runtime(conn, candidate, package, params) do
      {:ok, %{application: application, activation: activation}} ->
        response
        |> Map.put(:application, format_application(application))
        |> Map.put(:activation, format_activation(activation))

      _ ->
        response
    end
  end

  defp maybe_ensure_personal_runtime(
         conn,
         %PluginBundleCandidate{owner_scope_kind: "user"},
         package,
         params
       ) do
    workspace_id = params["workspace_id"] || params["workspaceId"]

    with workspace_id when is_binary(workspace_id) <- workspace_id,
         {_member, _role} <-
           Workspaces.get_member_with_role(workspace_id, conn.assigns.current_user_id),
         {:ok, result} <-
           ensure_promoted_user_package_runtime(conn, workspace_id, package) do
      {:ok, result}
    else
      _ -> :skip
    end
  end

  defp maybe_ensure_personal_runtime(_conn, _candidate, _package, _params), do: :skip

  defp ensure_promoted_user_package_runtime(conn, workspace_id, package) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    case Plugins.ensure_existing_personal_package_runtime(
           workspace_id,
           package,
           user_id,
           device_id
         ) do
      {:ok, result} ->
        {:ok, result}

      {:error, :plugin_application_not_found} ->
        Plugins.ensure_personal_package_runtime(workspace_id, package, user_id, device_id)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp authorize_activation_update(conn, %PluginActivation{user_id: user_id} = activation) do
    if user_id == conn.assigns.current_user_id do
      authorize_activation_device_update(conn, activation)
    else
      {:error, :not_found}
    end
  end

  defp authorize_activation_device_update(conn, %PluginActivation{device_id: device_id})
       when is_binary(device_id) do
    if conn.assigns.current_session.device_id == device_id do
      :ok
    else
      {:error, :plugin_activation_forbidden}
    end
  end

  defp authorize_activation_device_update(_conn, %PluginActivation{}), do: :ok

  defp maybe_put_param(attrs, key, params, param_key) do
    case Map.fetch(params, param_key) do
      {:ok, value} -> Map.put(attrs, key, value)
      :error -> attrs
    end
  end

  defp non_empty(value, error) when is_binary(value) do
    if String.trim(value) == "", do: {:error, error}, else: {:ok, value}
  end

  defp non_empty(_value, error), do: {:error, error}

  defp approval_attrs(conn, params) do
    %{
      approver_user_id: conn.assigns.current_user_id,
      approver_device_id: conn.assigns.current_session.device_id,
      approval_event_hash: params["approval_event_hash"],
      approval_epoch: params["approval_epoch"],
      previous_approval_event_hash: params["previous_approval_event_hash"],
      created_at_ms: params["created_at_ms"],
      hybrid_signature: params["hybrid_signature"]
    }
  end

  defp consent_attrs(conn, params) do
    %{
      package_id: params["package_id"],
      application_id: params["application_id"],
      activation_id: params["activation_id"],
      owner_scope_kind: params["owner_scope_kind"],
      application_scope_kind: params["application_scope_kind"] || "workspace",
      workspace_id: params["workspace_id"],
      plugin_id: params["plugin_id"],
      version: params["version"],
      bundle_hash: params["bundle_hash"],
      manifest_hash: params["manifest_hash"],
      resource_manifest_hash: params["resource_manifest_hash"],
      permissions_hash: params["permissions_hash"],
      endpoint_hash: params["endpoint_hash"],
      document_scope_hash: params["document_scope_hash"],
      user_id: conn.assigns.current_user_id,
      device_id: conn.assigns.current_session.device_id,
      signer_user_id: params["signer_user_id"],
      signer_device_id: params["signer_device_id"],
      decision: params["decision"],
      consent_epoch: params["consent_epoch"],
      previous_event_hash: params["previous_event_hash"],
      event_hash: params["event_hash"],
      hybrid_signature: params["hybrid_signature"]
    }
  end

  defp write_upload_archive(bytes) when is_binary(bytes), do: write_upload_archive(bytes, 3)

  defp write_upload_archive(_bytes, 0), do: {:error, :eexist}

  defp write_upload_archive(bytes, attempts) when is_binary(bytes) do
    path =
      Path.join(
        System.tmp_dir!(),
        "refmd-plugin-upload-#{random_archive_token()}.zip"
      )

    case File.open(path, [:write, :binary, :exclusive], fn file -> IO.binwrite(file, bytes) end) do
      {:ok, :ok} -> {:ok, path}
      {:error, :eexist} -> write_upload_archive(bytes, attempts - 1)
      {:error, reason} -> {:error, reason}
    end
  end

  defp random_archive_token do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp format_descriptor(descriptor),
    do: PluginRuntimeController.format_runtime_descriptor(descriptor)

  defp format_application(application) do
    application = Repo.preload(application, :current_bundle)

    %{
      id: application.id,
      package_id: application.package_id,
      plugin_id: application.plugin_id,
      workspace_id: application.workspace_id,
      application_scope_kind: application.application_scope_kind,
      application_mode: application.application_mode,
      workspace_policy_result: application.workspace_policy_result,
      enabled: application.enabled,
      consent_epoch: application.consent_epoch,
      state_head_hash: application.state_head_hash,
      current_bundle_id: application.current_bundle_id,
      network_endpoints: application_network_endpoints(application),
      deleted_at: application.deleted_at
    }
  end

  defp application_network_endpoints(%{current_bundle: %{manifest_json: manifest}})
       when is_map(manifest) do
    manifest
    |> get_in(["network", "endpoints"])
    |> list_value()
  end

  defp application_network_endpoints(_application), do: []

  defp format_activation(activation) do
    activation = Repo.preload(activation, application: :current_bundle)
    application = activation.application
    bundle = application && application.current_bundle

    %{
      id: activation.id,
      application_id: activation.application_id,
      workspace_id: application && application.workspace_id,
      package_id: application && application.package_id,
      plugin_id: application && application.plugin_id,
      bundle_hash: bundle && bundle.bundle_hash,
      user_id: activation.user_id,
      device_id: activation.device_id,
      activation_scope_kind: activation.activation_scope_kind,
      enabled: activation.enabled,
      deleted_at: activation.deleted_at
    }
  end

  defp format_package(package) do
    %{
      id: package.id,
      plugin_id: package.plugin_id,
      version: package.version,
      owner_scope_kind: package.owner_scope_kind,
      owner_workspace_id: package.owner_workspace_id,
      owner_user_id: package.owner_user_id,
      current_bundle_id: package.current_bundle_id,
      state_head_hash: package.state_head_hash,
      bundle_hash: package.bundle_hash,
      resource_manifest_hash: package.resource_manifest_hash
    }
  end

  defp format_candidate(conn, candidate) do
    %{
      id: candidate.id,
      plugin_id: candidate.plugin_id,
      version: candidate.version,
      owner_scope_kind: candidate.owner_scope_kind,
      owner_workspace_id: candidate.owner_workspace_id,
      owner_user_id: candidate.owner_user_id,
      workspace_id: candidate.workspace_id,
      source_kind: candidate.source_kind,
      source_url: candidate.source_url,
      source_url_hash: candidate.source_url_hash,
      archive_hash: candidate.archive_hash,
      validation_status: candidate.validation_status,
      validation_errors: candidate.validation_errors,
      bundle_hash: candidate.bundle_hash,
      manifest_hash: candidate.manifest_hash,
      main_js_hash: candidate.main_js_hash,
      styles_css_hash: candidate.styles_css_hash,
      resource_manifest_hash: candidate.resource_manifest_hash,
      resource_manifest: candidate.resource_manifest,
      permissions_hash: candidate.permissions_hash,
      endpoint_hash: candidate.endpoint_hash,
      renderer_slots_hash: candidate.renderer_slots_hash,
      document_scope_hash: candidate.document_scope_hash,
      capability_summary: capability_summary(candidate.manifest_json),
      scope_summary: scope_summary(candidate.manifest_json),
      approval_summary: approval_summary(conn, candidate)
    }
  end

  defp fetch_candidate(params) do
    case Plugins.get_bundle_candidate(params["candidate_id"]) do
      nil ->
        nil

      %PluginBundleCandidate{} = candidate ->
        if candidate.workspace_id == params["workspace_id"] do
          {:ok, candidate}
        else
          false
        end
    end
  end

  defp fetch_user_candidate(conn, params) do
    case Plugins.get_bundle_candidate(params["candidate_id"]) do
      nil ->
        nil

      %PluginBundleCandidate{} = candidate ->
        if candidate.owner_scope_kind == "user" and
             candidate.owner_user_id == conn.assigns.current_user_id and
             is_nil(candidate.workspace_id) do
          {:ok, candidate}
        else
          false
        end
    end
  end

  defp fetch_owned_candidate(conn, params) do
    case Plugins.get_bundle_candidate(params["candidate_id"]) do
      nil ->
        nil

      %PluginBundleCandidate{owner_scope_kind: "user"} = candidate ->
        if candidate.owner_user_id == conn.assigns.current_user_id and
             is_nil(candidate.workspace_id) do
          {:ok, candidate}
        else
          false
        end

      %PluginBundleCandidate{owner_scope_kind: "workspace"} = candidate ->
        case authorize_manifest_routed_workspace_context(conn, candidate.workspace_id) do
          :ok -> {:ok, candidate}
          {:error, _reason} -> false
        end

      %PluginBundleCandidate{} ->
        false
    end
  end

  defp capability_summary(manifest) when is_map(manifest) do
    %{
      permissions: list_value(Map.get(manifest, "permissions")),
      network_endpoints: list_value(get_in(manifest, ["network", "endpoints"])),
      renderer_slots: list_value(Map.get(manifest, "rendererSlots")),
      document_scopes: list_value(Map.get(manifest, "documentScopes"))
    }
  end

  defp capability_summary(_manifest) do
    %{
      permissions: [],
      network_endpoints: [],
      renderer_slots: [],
      document_scopes: []
    }
  end

  defp approval_summary(conn, candidate) do
    attrs = approval_summary_attrs(conn, candidate)

    with {:ok, device} <-
           Signing.fetch_active_device(attrs.approver_user_id, attrs.approver_device_id),
         actor <- approval_summary_actor(device, candidate),
         subject <- Plugins.plugin_bundle_approval_subject(candidate, attrs) do
      %{
        actor: actor,
        subject: subject,
        approval_event_hash: Plugins.plugin_bundle_approval_subject_hash(candidate, attrs),
        approval_epoch: attrs.approval_epoch,
        previous_approval_event_hash: attrs.previous_approval_event_hash,
        created_at_ms: attrs.created_at_ms
      }
    else
      _ -> nil
    end
  end

  defp approval_summary_attrs(conn, candidate) do
    {approval_epoch, previous_hash} = approval_chain(candidate)

    %{
      approver_user_id: conn.assigns.current_user_id,
      approver_device_id: conn.assigns.current_session.device_id,
      workspace_id: candidate.workspace_id,
      approval_epoch: approval_epoch,
      previous_approval_event_hash: previous_hash,
      created_at_ms: System.system_time(:millisecond)
    }
  end

  defp approval_chain(candidate) do
    Plugins.next_package_approval_chain(candidate.package_id)
  end

  defp approval_summary_actor(
         device,
         %PluginBundleCandidate{owner_scope_kind: "user"} = candidate
       ),
       do: Signing.actor(device, candidate.owner_user_id, "user")

  defp approval_summary_actor(device, %PluginBundleCandidate{} = candidate),
    do: Signing.actor(device, candidate.owner_workspace_id, "workspace")

  defp scope_summary(%{"scope" => scope}) when is_map(scope) do
    %{
      supported_owner_scopes:
        scope
        |> Map.get("supportedOwnerScopes")
        |> list_value()
        |> Enum.filter(&(&1 in ["user", "workspace"])),
      default_owner_scope: scope["defaultOwnerScope"],
      workspace_application: scope["workspaceApplication"]
    }
  end

  defp scope_summary(_manifest) do
    %{
      supported_owner_scopes: [],
      default_owner_scope: nil,
      workspace_application: nil
    }
  end

  defp list_value(value) when is_list(value), do: value
  defp list_value(_value), do: []

  defp error_response(conn, %Ecto.Changeset{} = changeset) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "validation_failed", details: inspect(changeset.errors)})
  end

  defp error_response(conn, reason)
       when reason in [
              :plugin_bundle_approval_forbidden,
              :plugin_bundle_approval_signature_invalid,
              :plugin_consent_event_signature_invalid,
              :plugin_activation_forbidden,
              :plugin_package_forbidden
            ] do
    conn |> put_status(:forbidden) |> json(%{error: to_string(reason)})
  end

  defp error_response(conn, :plugin_package_not_found), do: not_found(conn)

  defp error_response(conn, reason)
       when reason in [
              :plugin_bundle_approval_rollback,
              :plugin_bundle_approval_hash_mismatch,
              :stale_consent_head,
              :plugin_consent_event_hash_mismatch
            ] do
    conn |> put_status(:conflict) |> json(%{error: to_string(reason)})
  end

  defp error_response(conn, reason) when is_atom(reason),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})

  defp not_found(conn), do: conn |> put_status(:not_found) |> json(%{error: "not_found"})
end
