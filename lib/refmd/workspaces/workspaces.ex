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

  @spec create_default_workspace(Ecto.UUID.t(), String.t()) ::
          {:ok, Workspace.t()} | {:error, term()}
  def create_default_workspace(user_id, name) do
    slug = generate_slug(name)

    Repo.transaction(fn ->
      workspace =
        insert_or_rollback(
          %Workspace{}
          |> Workspace.changeset(%{name: name, slug: slug, owner_id: user_id})
        )

      roles =
        for {base_role, role_name} <- [
              {"owner", "Owner"},
              {"admin", "Admin"},
              {"editor", "Editor"},
              {"viewer", "Viewer"}
            ] do
          insert_or_rollback(
            %WorkspaceRole{created_at: DateTime.utc_now()}
            |> WorkspaceRole.changeset(%{
              workspace_id: workspace.id,
              name: role_name,
              base_role: base_role,
              is_default: base_role == "editor"
            })
          )
        end

      owner_role = Enum.find(roles, &(&1.base_role == "owner"))

      insert_or_rollback(
        %WorkspaceMember{joined_at: DateTime.utc_now()}
        |> WorkspaceMember.changeset(%{
          workspace_id: workspace.id,
          user_id: user_id,
          role_id: owner_role.id,
          is_default: true,
          joined_at: DateTime.utc_now()
        })
      )

      workspace
    end)
  end

  defp insert_or_rollback(changeset) do
    case Repo.insert(changeset) do
      {:ok, record} -> record
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  @spec get_workspace(Ecto.UUID.t()) :: Workspace.t() | nil
  def get_workspace(id), do: Repo.get(Workspace, id)

  @spec update_current_kek_version(Ecto.UUID.t(), integer()) ::
          {non_neg_integer(), nil | [term()]}
  def update_current_kek_version(workspace_id, version) do
    from(w in Workspace, where: w.id == ^workspace_id)
    |> Repo.update_all(set: [current_kek_version: version])
  end

  @spec initialize_kek_version(Ecto.UUID.t()) :: {non_neg_integer(), nil | [term()]}
  def initialize_kek_version(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id and w.current_kek_version == 0)
    |> Repo.update_all(set: [current_kek_version: 1])
  end

  @spec get_user_default_workspace(Ecto.UUID.t()) :: Workspace.t() | nil
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

  @spec list_user_workspaces(Ecto.UUID.t()) :: [Workspace.t()]
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

  @spec get_user_workspace_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def get_user_workspace_ids(user_id) do
    from(wm in WorkspaceMember,
      where: wm.user_id == ^user_id,
      select: wm.workspace_id
    )
    |> Repo.all()
  end

  @spec get_user_workspace_ids_with_kek_version(Ecto.UUID.t()) :: [{Ecto.UUID.t(), integer()}]
  def get_user_workspace_ids_with_kek_version(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id,
      select: {wm.workspace_id, w.current_kek_version}
    )
    |> Repo.all()
  end

  @spec mark_kek_rotation_needed([Ecto.UUID.t()], Ecto.UUID.t()) ::
          {non_neg_integer(), nil | [term()]}
  def mark_kek_rotation_needed(workspace_ids, initiator_user_id) when workspace_ids != [] do
    from(w in Workspace,
      where: w.id in ^workspace_ids and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [needs_kek_rotation: true, kek_rotation_initiator_user_id: initiator_user_id]
    )
  end

  def mark_kek_rotation_needed([], _initiator_user_id), do: {0, nil}

  @spec mark_dek_rotation_needed([Ecto.UUID.t()]) :: {non_neg_integer(), nil | [term()]}
  def mark_dek_rotation_needed(workspace_ids) when workspace_ids != [] do
    from(d in RefMD.Documents.Document,
      where: d.workspace_id in ^workspace_ids and d.needs_dek_rotation == false
    )
    |> Repo.update_all(set: [needs_dek_rotation: true])
  end

  def mark_dek_rotation_needed([]), do: {0, nil}

  @spec start_kek_rotation(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Workspace.t()} | {:error, :not_found | :kek_rotation_already_in_progress}
  def start_kek_rotation(workspace_id, initiator_user_id) do
    from(w in Workspace,
      where: w.id == ^workspace_id and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [
        needs_kek_rotation: true,
        kek_rotation_initiator_user_id: initiator_user_id
      ]
    )
    |> case do
      {1, _} ->
        {:ok, Repo.get!(Workspace, workspace_id)}

      {0, _} ->
        case Repo.get(Workspace, workspace_id) do
          nil -> {:error, :not_found}
          %{needs_kek_rotation: true} -> {:error, :kek_rotation_already_in_progress}
        end
    end
  end

  @spec complete_kek_rotation(Ecto.UUID.t(), integer(), keyword()) :: :ok | {:error, term()}
  def complete_kek_rotation(workspace_id, new_kek_version, opts \\ []) do
    envelope_checks = Keyword.get(opts, :envelope_checks, fn -> :ok end)

    Repo.transaction(fn ->
      workspace =
        from(w in Workspace,
          where: w.id == ^workspace_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      cond do
        workspace == nil ->
          Repo.rollback(:not_found)

        not workspace.needs_kek_rotation ->
          Repo.rollback(:not_in_rotation)

        workspace.current_kek_version >= new_kek_version ->
          Repo.rollback(:version_not_monotonic)

        true ->
          apply_rotation_completion(workspace_id, new_kek_version, envelope_checks)
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp apply_rotation_completion(workspace_id, new_kek_version, envelope_checks) do
    case envelope_checks.() do
      :ok ->
        # Deactivate old KEK version keys (min_kek_version = new version rejects old KEK)
        from(k in RefMD.Encryption.WorkspaceEncryptedKey,
          where:
            k.workspace_id == ^workspace_id and
              k.key_version < ^new_kek_version and
              k.is_active == true
        )
        |> Repo.update_all(set: [is_active: false])

        from(w in Workspace, where: w.id == ^workspace_id)
        |> Repo.update_all(
          set: [
            current_kek_version: new_kek_version,
            min_kek_version: new_kek_version,
            needs_kek_rotation: false,
            kek_rotation_initiator_user_id: nil
          ]
        )

        :ok

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  @spec list_workspaces_needing_kek_rotation() :: [map()]
  def list_workspaces_needing_kek_rotation do
    from(w in Workspace,
      where: w.needs_kek_rotation == true,
      select: %{
        workspace_id: w.id,
        initiator_user_id: w.kek_rotation_initiator_user_id,
        current_kek_version: w.current_kek_version
      }
    )
    |> Repo.all()
  end

  @spec list_workspace_member_user_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def list_workspace_member_user_ids(workspace_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id,
      select: wm.user_id
    )
    |> Repo.all()
  end

  @spec get_workspace_member(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceMember.t() | nil
  def get_workspace_member(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id
    )
    |> Repo.one()
  end

  @spec get_member_role(Ecto.UUID.t(), Ecto.UUID.t()) :: String.t() | nil
  def get_member_role(workspace_id, user_id) do
    from(wm in WorkspaceMember,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id and r.workspace_id == wm.workspace_id,
      where: wm.workspace_id == ^workspace_id and wm.user_id == ^user_id,
      select: r.base_role
    )
    |> Repo.one()
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
