defmodule RefMDWeb.WorkspaceController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Workspaces
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.RequireRBAC, [permission: :membership] when action in [:show]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:update"] when action in [:update]

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
      %{}
      |> maybe_put_string(:description, params["description"])
      |> maybe_put_string(:icon, params["icon"])

    case Workspaces.create_workspace(user_id, name, opts) do
      {:ok, workspace} ->
        conn
        |> put_status(:created)
        |> json(serialize_workspace(workspace))

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: format_errors(changeset)})
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
    results = Workspaces.list_user_workspaces(user_id)

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

    attrs =
      params
      |> Map.take(["name", "slug", "description", "icon"])
      |> Enum.into(%{}, fn {k, v} -> {String.to_existing_atom(k), v} end)

    case Workspaces.update_workspace(workspace, attrs) do
      {:ok, updated} ->
        json(conn, serialize_workspace(updated))

      {:error, changeset} ->
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

  defp serialize_workspace(workspace) do
    %{
      id: workspace.id,
      name: workspace.name,
      slug: workspace.slug,
      description: workspace.description,
      icon: workspace.icon,
      owner_id: workspace.owner_id,
      current_kek_version: workspace.current_kek_version,
      needs_kek_rotation: workspace.needs_kek_rotation,
      kek_rotation_initiator_user_id: workspace.kek_rotation_initiator_user_id,
      created_at: workspace.created_at,
      updated_at: workspace.updated_at
    }
  end
end
