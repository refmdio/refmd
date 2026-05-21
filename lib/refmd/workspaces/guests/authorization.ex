defmodule RefMD.Workspaces.Guests.Authorization do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo
  alias RefMD.Users

  alias RefMD.Workspaces.{
    WorkspaceGuestGrant,
    WorkspaceRole,
    WorkspaceRolePermission
  }

  @base_role_defaults %{
    "owner" => MapSet.new(~w(
        document:read document:write document:manage_share document:delete document:archive
        workspace:update workspace:admin workspace:delete
        member:list member:invite guest:invite member:change_role member:remove
        role:manage
      )),
    "admin" => MapSet.new(~w(
        document:read document:write document:manage_share document:delete document:archive
        workspace:update workspace:admin
        member:list member:invite guest:invite member:change_role member:remove
        role:manage
      )),
    "editor" =>
      MapSet.new(
        ~w(document:read document:write document:manage_share document:archive member:list)
      ),
    "viewer" => MapSet.new(~w(document:read member:list)),
    "guest" => MapSet.new(~w(document:read document:write document:archive))
  }

  @spec guest_user?(Ecto.UUID.t()) :: boolean()
  def guest_user?(user_id) do
    from(u in Users.User, where: u.id == ^user_id, select: u.account_type == "guest")
    |> Repo.one()
    |> Kernel.==(true)
  end

  @spec role_for_active_grants(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceRole.t() | nil
  def role_for_active_grants(workspace_id, user_id) do
    if active_grants(workspace_id, user_id) == [] do
      nil
    else
      guest_workspace_role(workspace_id)
    end
  end

  @spec authorize_permission(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          atom() | String.t(),
          Document.t() | nil
        ) ::
          :ok | {:error, atom()}
  def authorize_permission(workspace_id, user_id, permission, document_or_conn \\ nil) do
    grants = active_grants(workspace_id, user_id)
    role = role_for_active_grants(workspace_id, user_id)

    cond do
      guest_context_invalid?(grants, role) -> {:error, :permission_denied}
      document_permission_denied?(role, permission) -> {:error, :permission_denied}
      true -> authorize_guest_permission(permission, grants, document_or_conn)
    end
  end

  defp guest_context_invalid?(grants, role), do: grants == [] or is_nil(role)

  defp document_permission_denied?(role, permission) do
    permission in ["document:read", "document:write", "document:archive"] and
      not permission_granted?(role, permission)
  end

  defp authorize_guest_permission(:membership, _grants, _document_or_conn), do: :ok

  defp authorize_guest_permission("member:list", _grants, _document_or_conn),
    do: {:error, :permission_denied}

  defp authorize_guest_permission("document:read", _grants, nil), do: :ok

  defp authorize_guest_permission("document:read", grants, document_or_conn) do
    if Enum.any?(grants, &grant_covers_document?(&1, document_or_conn)),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_guest_permission("document:write", grants, %Document{} = document) do
    authorize_write(grants, document)
  end

  defp authorize_guest_permission("document:archive", grants, %Document{} = document) do
    authorize_archive(grants, document)
  end

  defp authorize_guest_permission(_permission, _grants, _document_or_conn),
    do: {:error, :permission_denied}

  @spec authorize_document_create(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), Ecto.UUID.t() | nil) ::
          :ok | {:error, atom()}
  def authorize_document_create(workspace_id, user_id, doc_type, parent_id)
      when doc_type in ["document", "folder"] do
    grants = active_grants(workspace_id, user_id)
    role = role_for_active_grants(workspace_id, user_id)

    cond do
      grants == [] or is_nil(role) ->
        {:error, :permission_denied}

      not permission_granted?(role, "document:write") ->
        {:error, :permission_denied}

      true ->
        authorize_create(grants, %{"doc_type" => doc_type, "parent_id" => parent_id})
    end
  end

  def authorize_document_create(_workspace_id, _user_id, _doc_type, _parent_id),
    do: {:error, :permission_denied}

  @spec authorize_document_reorder(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil,
          Ecto.UUID.t() | nil
        ) ::
          :ok | {:error, atom()}
  def authorize_document_reorder(workspace_id, user_id, document_id, parent_id) do
    grants = active_grants(workspace_id, user_id)
    role = role_for_active_grants(workspace_id, user_id)

    cond do
      grants == [] or is_nil(role) ->
        {:error, :permission_denied}

      not permission_granted?(role, "document:write") ->
        {:error, :permission_denied}

      true ->
        authorize_reorder(grants, %{"document_id" => document_id, "parent_id" => parent_id})
    end
  end

  @spec filter_documents(Ecto.UUID.t(), Ecto.UUID.t(), [Document.t()]) :: [Document.t()]
  def filter_documents(workspace_id, user_id, documents) do
    if guest_user?(user_id) do
      Enum.filter(documents, fn document ->
        authorize_permission(workspace_id, user_id, "document:read", document) == :ok
      end)
    else
      documents
    end
  end

  defp active_grants(workspace_id, user_id) do
    from(g in WorkspaceGuestGrant,
      where:
        g.workspace_id == ^workspace_id and
          g.user_id == ^user_id and
          is_nil(g.revoked_at)
    )
    |> Repo.all()
  end

  defp guest_workspace_role(workspace_id) do
    query =
      from(r in WorkspaceRole,
        left_join: p in WorkspaceRolePermission,
        on: p.role_id == r.id,
        where:
          r.workspace_id == ^workspace_id and
            r.base_role == "guest" and
            is_nil(r.catalog_version),
        select: {r, p}
      )

    case Repo.all(query) do
      [] ->
        nil

      rows ->
        {role, _permission} = hd(rows)

        permissions =
          rows
          |> Enum.map(fn {_role, permission} -> permission end)
          |> Enum.reject(&is_nil/1)

        %{role | permissions: permissions}
    end
  end

  defp permission_granted?(%{base_role: "owner"}, _permission), do: true

  defp permission_granted?(role, permission) do
    defaults = Map.get(@base_role_defaults, role.base_role, MapSet.new())

    case Enum.find(role.permissions || [], &(&1.permission == permission)) do
      nil -> MapSet.member?(defaults, permission)
      override -> override.granted
    end
  end

  defp active_document?(%Document{workspace_id: workspace_id}, workspace_id), do: true
  defp active_document?(_, _), do: false

  defp authorize_write(grants, %Document{} = document) do
    if Enum.any?(grants, &(&1.permission == "edit" and grant_covers_document?(&1, document))),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_archive(grants, %Document{} = document) do
    if Enum.any?(grants, &(&1.permission == "edit" and grant_covers_document?(&1, document))),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_create(grants, %{"doc_type" => doc_type} = params)
       when doc_type in ["document", "folder"] do
    parent =
      case Map.get(params, "parent_id") do
        nil -> nil
        parent_id -> Repo.get(Document, parent_id)
      end

    if Enum.any?(grants, &grant_allows_create?(&1, parent)),
      do: :ok,
      else: {:error, :permission_denied}
  end

  defp authorize_create(_grants, _params), do: {:error, :permission_denied}

  defp grant_allows_create?(
         %WorkspaceGuestGrant{permission: "edit", scope_kind: "workspace"},
         _parent
       ),
       do: true

  defp grant_allows_create?(
         %WorkspaceGuestGrant{permission: "edit", scope_kind: "folder"} = grant,
         %Document{} = parent
       ) do
    grant_covers_document?(grant, parent)
  end

  defp grant_allows_create?(_grant, _parent), do: false

  defp authorize_reorder(grants, %{"document_id" => document_id} = params) do
    document = Repo.get(Document, document_id)

    parent =
      case Map.get(params, "parent_id") do
        nil -> nil
        parent_id -> Repo.get(Document, parent_id)
      end

    if document &&
         Enum.any?(grants, fn grant ->
           grant.permission == "edit" and grant_allows_reorder_document?(grant, document, parent)
         end) do
      :ok
    else
      {:error, :permission_denied}
    end
  end

  defp grant_allows_reorder_document?(
         %WorkspaceGuestGrant{scope_kind: "workspace"},
         _document,
         _parent
       ),
       do: true

  defp grant_allows_reorder_document?(
         %WorkspaceGuestGrant{scope_kind: "folder"},
         %Document{},
         nil
       ),
       do: false

  defp grant_allows_reorder_document?(
         %WorkspaceGuestGrant{scope_kind: "folder"} = grant,
         %Document{} = document,
         %Document{} = parent
       ) do
    grant_covers_document?(grant, document) and grant_covers_document?(grant, parent)
  end

  defp grant_allows_reorder_document?(_grant, _document, _parent), do: false

  defp grant_covers_document?(%WorkspaceGuestGrant{scope_kind: "workspace"} = grant, document) do
    active_document?(document, grant.workspace_id)
  end

  defp grant_covers_document?(
         %WorkspaceGuestGrant{scope_kind: "document", scope_id: target_id},
         %Document{id: document_id}
       ) do
    target_id == document_id
  end

  defp grant_covers_document?(
         %WorkspaceGuestGrant{scope_kind: "folder", scope_id: folder_id},
         %Document{id: document_id}
       ) do
    document_id == folder_id or document_descends_from?(document_id, folder_id)
  end

  defp document_descends_from?(document_id, folder_id) do
    case Repo.get(Document, document_id) do
      nil ->
        false

      %Document{parent_id: nil} ->
        false

      %Document{parent_id: ^folder_id} ->
        true

      %Document{parent_id: parent_id} ->
        document_descends_from?(parent_id, folder_id)
    end
  end
end
