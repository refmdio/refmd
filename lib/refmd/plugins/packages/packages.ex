defmodule RefMD.Plugins.Packages do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Plugins.PluginPackage
  alias RefMD.Repo

  @genesis_event_hash "GENESIS"

  def create(attrs) when is_map(attrs) do
    %PluginPackage{id: Map.get(attrs, :id) || Map.get(attrs, "id")}
    |> PluginPackage.changeset(Map.put_new(attrs, :state_head_hash, @genesis_event_hash))
    |> Repo.insert()
  end

  def get(id), do: Repo.get(PluginPackage, id)

  def list_for_user(user_id) do
    Repo.all(
      from(p in PluginPackage,
        where: p.owner_scope_kind == "user" and p.owner_user_id == ^user_id,
        order_by: [asc: p.plugin_id, desc: p.created_at]
      )
    )
  end

  def list_for_workspace(workspace_id) do
    Repo.all(
      from(p in PluginPackage,
        where: p.owner_scope_kind == "workspace" and p.owner_workspace_id == ^workspace_id,
        order_by: [asc: p.plugin_id, desc: p.created_at]
      )
    )
  end

  def pin_current(%PluginPackage{} = package, bundle) do
    package
    |> PluginPackage.changeset(%{
      plugin_id: package.plugin_id,
      version: bundle.version,
      owner_scope_kind: package.owner_scope_kind,
      owner_workspace_id: package.owner_workspace_id,
      owner_user_id: package.owner_user_id,
      bundle_hash: bundle.bundle_hash,
      resource_manifest_hash: bundle.resource_manifest_hash,
      state_head_hash: bundle.approval_event_hash,
      current_bundle_id: bundle.id
    })
    |> Repo.update()
  end
end
