defmodule RefMDWeb.WorkspaceController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Crypto.Encoding
  alias RefMD.{Public, Workspaces}
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.RequireRBAC, [permission: :membership] when action in [:show]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:update"] when action in [:update]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:features"] when action in [:update_features]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:delete"] when action in [:delete]

  # ── POST /api/workspaces ──────────────────────────────

  operation(:create,
    summary: "Create a new workspace",
    request_body: {"Workspace params", "application/json", Schemas.CreateWorkspaceRequest},
    responses: [
      created: {"Created workspace", "application/json", Schemas.WorkspaceResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, %{"name" => name} = params) do
    user_id = conn.assigns.current_user_id

    opts =
      %{
        workspace_id: params["workspace_id"],
        workspace_owner_role_id: params["workspace_owner_role_id"],
        key_directory: %{
          workspace_events: params["workspace_key_directory_events"],
          workspace_checkpoint: params["workspace_key_directory_checkpoint"]
        },
        creator_device_id: conn.assigns.current_session.device_id
      }
      |> maybe_put_string(:description, params["description"])
      |> maybe_put_string(:icon, params["icon"])

    case Workspaces.create_workspace(user_id, name, opts) do
      {:ok, workspace} ->
        conn
        |> put_status(:created)
        |> json(serialize_workspace(workspace))

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: format_errors(changeset)})

      {:error, reason} when is_atom(reason) ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: Atom.to_string(reason)})
    end
  end

  def create(conn, _params) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_name"})
  end

  # ── GET /api/workspaces ───────────────────────────────

  operation(:index,
    summary: "List workspaces the current user belongs to",
    responses: [
      ok: {"Workspace list", "application/json", Schemas.WorkspacesListResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    user_id = conn.assigns.current_user_id
    results = Workspaces.list_discoverable_workspaces(user_id)

    json(conn, %{
      workspaces:
        Enum.map(results, fn %{
                               workspace: ws,
                               is_default: is_default,
                               role_id: role_id,
                               base_role: base_role
                             } ->
          ws
          |> serialize_workspace()
          |> Map.put(:is_default, is_default)
          |> Map.put(:current_user_role_id, role_id)
          |> Map.put(:current_user_base_role, base_role)
        end)
    })
  end

  # ── GET /api/workspaces/:workspace_id ─────────────────

  operation(:show,
    summary: "Get workspace details",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Workspace details", "application/json", Schemas.WorkspaceResponse},
      forbidden: {"Not a member", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    workspace = Workspaces.get_workspace(conn.assigns.workspace_id)
    role = conn.assigns.workspace_role

    workspace
    |> serialize_workspace()
    |> Map.put(:current_user_role_id, role.id)
    |> Map.put(:current_user_base_role, role.base_role)
    |> then(&json(conn, &1))
  end

  # ── PATCH /api/workspaces/:workspace_id ───────────────

  operation(:update,
    summary: "Update workspace name, description, or icon",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Update params", "application/json", Schemas.UpdateWorkspaceRequest},
    responses: [
      ok: {"Updated workspace", "application/json", Schemas.WorkspaceResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update(conn, params) do
    workspace = Workspaces.get_workspace(conn.assigns.workspace_id)

    case build_update_attrs(params) do
      {:ok, attrs} ->
        case Workspaces.update_workspace(workspace, attrs) do
          {:ok, updated} ->
            json(conn, serialize_workspace(updated))

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "validation_error", details: format_errors(changeset)})
        end

      {:error, field} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_value", field: field})
    end
  end

  operation(:update_features,
    summary: "Update workspace feature settings",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Feature params", "application/json", Schemas.UpdateWorkspaceFeaturesRequest},
    responses: [
      ok: {"Updated workspace", "application/json", Schemas.WorkspaceResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update_features(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update_features(conn, params) do
    workspace = Workspaces.get_workspace(conn.assigns.workspace_id)

    with {:ok, attrs} <- build_feature_attrs(params),
         {:ok, updated} <- Workspaces.update_workspace(workspace, attrs),
         {:ok, _profile} <- maybe_update_author_profile(updated.id, params) do
      json(conn, serialize_workspace(updated))
    else
      {:error, field} when is_binary(field) ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_value", field: field})

      {:error, :invalid_value} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_value"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: format_errors(changeset)})
    end
  end

  # ── DELETE /api/workspaces/:workspace_id ──────────────

  operation(:delete,
    summary: "Delete a workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Deleted", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, _params) do
    workspace = Workspaces.get_workspace(conn.assigns.workspace_id)

    case Workspaces.delete_workspace(workspace) do
      {:ok, _} ->
        json(conn, %{ok: true})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "delete_failed", details: format_errors(changeset)})
    end
  end

  # ── Helpers ───────────────────────────────────────────

  defp maybe_put_string(map, _key, nil), do: map
  defp maybe_put_string(map, key, value) when is_binary(value), do: Map.put(map, key, value)
  defp maybe_put_string(map, _key, _value), do: map

  defp build_update_attrs(params) do
    with {:ok, guest_invites_enabled} <- parse_optional_boolean(params, "guest_invites_enabled"),
         {:ok, guest_member_limit} <- parse_optional_integer(params, "guest_member_limit") do
      attrs =
        params
        |> Map.take([
          "name",
          "slug",
          "description",
          "icon",
          "encrypted_name",
          "encrypted_name_nonce",
          "encrypted_name_key_version",
          "encrypted_description",
          "encrypted_description_nonce",
          "encrypted_description_key_version",
          "encrypted_icon",
          "encrypted_icon_nonce",
          "encrypted_icon_key_version"
        ])
        |> decode_workspace_binary_fields()
        |> maybe_put_parsed_param("guest_invites_enabled", guest_invites_enabled)
        |> maybe_put_parsed_param("guest_member_limit", guest_member_limit)
        |> Enum.into(%{}, fn {k, v} -> {String.to_existing_atom(k), v} end)

      {:ok, attrs}
    end
  end

  defp decode_workspace_binary_fields(attrs) do
    Enum.reduce(
      [
        "encrypted_name",
        "encrypted_name_nonce",
        "encrypted_description",
        "encrypted_description_nonce",
        "encrypted_icon",
        "encrypted_icon_nonce"
      ],
      attrs,
      fn key, acc ->
        decode_workspace_binary_field(acc, key, Map.get(acc, key))
      end
    )
  end

  defp decode_workspace_binary_field(attrs, key, value) when is_binary(value) do
    Map.put(attrs, key, Encoding.decode_base64url!(value))
  rescue
    ArgumentError -> attrs
  end

  defp decode_workspace_binary_field(attrs, _key, _value), do: attrs

  defp build_feature_attrs(params) do
    with {:ok, share_links_enabled} <- parse_optional_boolean(params, "share_links_enabled"),
         {:ok, public_publishing_enabled} <-
           parse_optional_boolean(params, "public_publishing_enabled"),
         {:ok, guest_invites_enabled} <- parse_optional_boolean(params, "guest_invites_enabled"),
         {:ok, guest_member_limit} <- parse_optional_integer(params, "guest_member_limit") do
      attrs =
        %{}
        |> maybe_put_parsed_param("share_links_enabled", share_links_enabled)
        |> maybe_put_parsed_param("public_publishing_enabled", public_publishing_enabled)
        |> maybe_put_parsed_param("guest_invites_enabled", guest_invites_enabled)
        |> maybe_put_parsed_param("guest_member_limit", guest_member_limit)
        |> maybe_put_parsed_param(
          "plugin_network_proxy",
          Map.get(params, "plugin_network_proxy", :missing)
        )
        |> maybe_put_parsed_param(
          "plugin_user_policy",
          Map.get(params, "plugin_user_policy", :missing)
        )
        |> Enum.into(%{}, fn {k, v} -> {String.to_existing_atom(k), v} end)

      {:ok, attrs}
    end
  end

  defp maybe_update_author_profile(workspace_id, params) do
    if Enum.any?(
         ["public_author_display_name", "public_author_slug", "public_author_bio"],
         &Map.has_key?(params, &1)
       ) do
      Public.upsert_author_profile(workspace_id, params)
    else
      {:ok, nil}
    end
  end

  defp parse_optional_boolean(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when is_boolean(value) -> {:ok, value}
      {:ok, _value} -> {:error, key}
      :error -> {:ok, :missing}
    end
  end

  defp parse_optional_integer(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when is_integer(value) or is_nil(value) -> {:ok, value}
      {:ok, _value} -> {:error, key}
      :error -> {:ok, :missing}
    end
  end

  defp maybe_put_parsed_param(map, _key, :missing), do: map
  defp maybe_put_parsed_param(map, key, value), do: Map.put(map, key, value)

  defp serialize_workspace(workspace) do
    %{
      id: workspace.id,
      name: workspace.name,
      slug: workspace.slug,
      description: workspace.description,
      icon: workspace.icon,
      encrypted_name: encode_workspace_binary(workspace.encrypted_name),
      encrypted_name_nonce: encode_workspace_binary(workspace.encrypted_name_nonce),
      encrypted_name_key_version: workspace.encrypted_name_key_version,
      encrypted_description: encode_workspace_binary(workspace.encrypted_description),
      encrypted_description_nonce: encode_workspace_binary(workspace.encrypted_description_nonce),
      encrypted_description_key_version: workspace.encrypted_description_key_version,
      encrypted_icon: encode_workspace_binary(workspace.encrypted_icon),
      encrypted_icon_nonce: encode_workspace_binary(workspace.encrypted_icon_nonce),
      encrypted_icon_key_version: workspace.encrypted_icon_key_version,
      owner_id: workspace.owner_id,
      share_links_enabled: workspace.share_links_enabled,
      public_publishing_enabled: workspace.public_publishing_enabled,
      public_author_profile: Public.get_author_profile(workspace.id),
      guest_invites_enabled: workspace.guest_invites_enabled,
      guest_member_limit: workspace.guest_member_limit,
      plugin_network_proxy: workspace.plugin_network_proxy,
      plugin_user_policy: workspace.plugin_user_policy,
      current_kek_version: workspace.current_kek_version,
      needs_kek_rotation: workspace.needs_kek_rotation,
      kek_rotation_initiator_user_id: workspace.kek_rotation_initiator_user_id,
      created_at: workspace.created_at,
      updated_at: workspace.updated_at
    }
  end

  defp encode_workspace_binary(nil), do: nil

  defp encode_workspace_binary(value) when is_binary(value),
    do: Base.url_encode64(value, padding: false)
end
