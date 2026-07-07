defmodule RefMDWeb.Plugs.RequireRBAC do
  @moduledoc """
  Plug that enforces RBAC permission checks for workspace-scoped endpoints.

  Usage:
    plug RequireRBAC, permission: "document:read"
    plug RequireRBAC, permission: :membership
    plug RequireRBAC, permission: "member:invite", not_member_status: :not_found

  Options:
    - `permission` (required): permission string or `:membership`
    - `not_member_status`: `:forbidden` (default) or `:not_found`

  Requires RequireAuth (and typically RequirePoP) to run first.
  Resolves workspace_id from path params, fetches membership and role,
  then checks the requested permission against the role's effective permissions.

  Assigns to conn:
    - :workspace_id
    - :workspace_member
    - :workspace_role
  """

  import Plug.Conn
  alias RefMD.Workspaces

  def init(opts) do
    permission = Keyword.fetch!(opts, :permission)
    not_member_status = Keyword.get(opts, :not_member_status, :forbidden)

    unless not_member_status in [:forbidden, :not_found] do
      raise ArgumentError,
            "not_member_status must be :forbidden or :not_found, got: #{inspect(not_member_status)}"
    end

    if permission != :membership do
      unless Workspaces.permission_defined?(permission) do
        raise ArgumentError, "Unknown permission: #{inspect(permission)}"
      end
    end

    %{permission: permission, not_member_status: not_member_status}
  end

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i

  def call(conn, %{permission: permission, not_member_status: not_member_status}) do
    workspace_id =
      conn.path_params["workspace_id"] || conn.assigns[:workspace_id] ||
        conn.params["workspace_id"]

    if Regex.match?(@uuid_regex, workspace_id || "") do
      do_call(conn, workspace_id, permission, not_member_status)
    else
      conn
      |> put_status(:bad_request)
      |> Phoenix.Controller.json(%{error: "invalid_workspace_id"})
      |> halt()
    end
  end

  defp do_call(conn, workspace_id, permission, not_member_status) do
    user_id = conn.assigns.current_user_id

    case Workspaces.get_member_with_role(workspace_id, user_id) do
      nil ->
        maybe_authorize_guest_without_membership(
          conn,
          workspace_id,
          user_id,
          permission,
          not_member_status
        )

      {member, role} ->
        conn = assign_workspace_context(conn, workspace_id, member, role)

        if permission == :membership do
          maybe_enforce_guest_scope(conn, :membership)
        else
          check_permission(conn, permission, role)
        end
    end
  end

  defp maybe_authorize_guest_without_membership(
         conn,
         workspace_id,
         user_id,
         permission,
         not_member_status
       ) do
    with true <- Workspaces.guest_user?(user_id),
         {:ok, role} <- fetch_guest_role_for_active_grants(workspace_id, user_id) do
      authorize_guest_without_membership(conn, workspace_id, user_id, permission, role)
    else
      _ -> deny_not_member(conn, not_member_status)
    end
  end

  defp fetch_guest_role_for_active_grants(workspace_id, user_id) do
    case Workspaces.guest_role_for_active_grants(workspace_id, user_id) do
      nil -> :error
      role -> {:ok, role}
    end
  end

  defp authorize_guest_without_membership(conn, workspace_id, user_id, permission, role) do
    member = %{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: role.id,
      is_default: false
    }

    conn = assign_workspace_context(conn, workspace_id, member, role)

    if permission == :membership do
      maybe_enforce_guest_scope(conn, :membership)
    else
      check_permission(conn, permission, role)
    end
  end

  defp check_permission(conn, permission, role) do
    if Workspaces.permission_granted?(role, permission) do
      maybe_enforce_guest_scope(conn, permission)
    else
      deny(conn)
    end
  end

  defp maybe_enforce_guest_scope(conn, permission) do
    if Workspaces.guest_user?(conn.assigns.current_user_id) do
      authorize_guest_scope(conn, permission)
    else
      conn
    end
  end

  defp authorize_guest_scope(%{assigns: %{allow_guest_crypto_access: true}} = conn, :membership) do
    case Workspaces.authorize_guest_permission(
           conn.assigns.workspace_id,
           conn.assigns.current_user_id,
           "document:read",
           nil
         ) do
      :ok -> conn
      {:error, _reason} -> deny(conn)
    end
  end

  defp authorize_guest_scope(conn, permission) do
    case guest_authorization_result(conn, permission) do
      :ok -> conn
      {:error, _reason} -> deny(conn)
    end
  end

  defp guest_authorization_result(%{assigns: %{document: document}} = conn, "document:write") do
    if Map.has_key?(conn.params, "parent_id") do
      Workspaces.authorize_guest_document_reorder(
        conn.assigns.workspace_id,
        conn.assigns.current_user_id,
        document.id,
        conn.params["parent_id"]
      )
    else
      Workspaces.authorize_guest_permission(
        conn.assigns.workspace_id,
        conn.assigns.current_user_id,
        "document:write",
        document
      )
    end
  end

  defp guest_authorization_result(%{assigns: %{document: document}} = conn, permission)
       when permission in ["document:read", "document:archive"] do
    Workspaces.authorize_guest_permission(
      conn.assigns.workspace_id,
      conn.assigns.current_user_id,
      permission,
      document
    )
  end

  defp guest_authorization_result(conn, "document:read") do
    Workspaces.authorize_guest_permission(
      conn.assigns.workspace_id,
      conn.assigns.current_user_id,
      "document:read",
      nil
    )
  end

  defp guest_authorization_result(conn, "document:write") do
    cond do
      Map.has_key?(conn.params, "doc_type") ->
        Workspaces.authorize_guest_document_create(
          conn.assigns.workspace_id,
          conn.assigns.current_user_id,
          conn.params["doc_type"],
          conn.params["parent_id"]
        )

      Map.has_key?(conn.params, "document_id") and Map.has_key?(conn.params, "position") ->
        Workspaces.authorize_guest_document_reorder(
          conn.assigns.workspace_id,
          conn.assigns.current_user_id,
          conn.params["document_id"],
          conn.params["parent_id"]
        )

      true ->
        {:error, :permission_denied}
    end
  end

  defp guest_authorization_result(conn, permission) do
    Workspaces.authorize_guest_permission(
      conn.assigns.workspace_id,
      conn.assigns.current_user_id,
      permission,
      nil
    )
  end

  defp deny(conn) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{error: "permission_denied"})
    |> halt()
  end

  defp deny_not_member(conn, :forbidden) do
    conn
    |> put_status(:forbidden)
    |> Phoenix.Controller.json(%{error: "not_a_member"})
    |> halt()
  end

  defp deny_not_member(conn, :not_found) do
    conn
    |> put_status(:not_found)
    |> Phoenix.Controller.json(%{error: "not_found"})
    |> halt()
  end

  defp assign_workspace_context(conn, workspace_id, member, role) do
    conn
    |> assign(:workspace_id, workspace_id)
    |> assign(:workspace_member, member)
    |> assign(:workspace_role, role)
  end
end
