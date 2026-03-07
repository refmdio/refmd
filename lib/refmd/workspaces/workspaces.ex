defmodule RefMD.Workspaces do
  @moduledoc """
  The Workspaces context. Manages workspaces, members, roles, and permissions.
  """

  import Ecto.Query
  alias RefMD.Repo

  alias RefMD.Workspaces.{
    Workspace,
    WorkspaceMember,
    WorkspaceRole
  }

  def create_default_workspace(user_id, name) do
    slug = generate_slug(name)

    Repo.transaction(fn ->
      {:ok, workspace} =
        %Workspace{}
        |> Workspace.changeset(%{name: name, slug: slug, owner_id: user_id})
        |> Repo.insert()

      roles =
        for {base_role, role_name} <- [
              {"owner", "Owner"},
              {"admin", "Admin"},
              {"editor", "Editor"},
              {"viewer", "Viewer"}
            ] do
          {:ok, role} =
            %WorkspaceRole{created_at: DateTime.utc_now()}
            |> WorkspaceRole.changeset(%{
              workspace_id: workspace.id,
              name: role_name,
              base_role: base_role,
              is_default: base_role == "editor"
            })
            |> Repo.insert()

          role
        end

      owner_role = Enum.find(roles, &(&1.base_role == "owner"))

      {:ok, _member} =
        %WorkspaceMember{joined_at: DateTime.utc_now()}
        |> WorkspaceMember.changeset(%{
          workspace_id: workspace.id,
          user_id: user_id,
          role_id: owner_role.id,
          is_default: true,
          joined_at: DateTime.utc_now()
        })
        |> Repo.insert()

      workspace
    end)
  end

  def get_workspace(id), do: Repo.get(Workspace, id)

  def update_current_kek_version(workspace_id, version) do
    from(w in Workspace, where: w.id == ^workspace_id)
    |> Repo.update_all(set: [current_kek_version: version])
  end

  def get_user_default_workspace(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id and wm.is_default == true,
      select: w,
      limit: 1
    )
    |> Repo.one()
  end

  def list_user_workspaces(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id,
      select: w,
      order_by: [asc: w.name]
    )
    |> Repo.all()
  end

  defp generate_slug(name) do
    base =
      name
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")

    suffix =
      :crypto.strong_rand_bytes(4)
      |> Base.url_encode64(padding: false)
      |> String.downcase()

    "#{base}-#{suffix}"
  end
end
