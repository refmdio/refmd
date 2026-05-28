defmodule RefMD.Repo.Migrations.AddPluginPackageOwnerUniqueness do
  use Ecto.Migration

  def change do
    create_if_not_exists unique_index(
                           :plugin_packages,
                           [
                             :owner_scope_kind,
                             :owner_workspace_id,
                             :plugin_id,
                             :version,
                             :bundle_hash
                           ],
                           name: :plugin_packages_workspace_owner_package_index,
                           where: "owner_scope_kind = 'workspace'"
                         )

    create_if_not_exists unique_index(
                           :plugin_packages,
                           [
                             :owner_scope_kind,
                             :owner_user_id,
                             :plugin_id,
                             :version,
                             :bundle_hash
                           ],
                           name: :plugin_packages_user_owner_package_index,
                           where: "owner_scope_kind = 'user'"
                         )
  end
end
