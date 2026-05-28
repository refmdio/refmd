defmodule RefMD.Repo.Migrations.AddPluginNetworkProxySettings do
  use Ecto.Migration

  def change do
    alter table(:user_settings) do
      add :plugin_network_proxy, :map
    end

    alter table(:workspaces) do
      add :plugin_network_proxy, :map
    end
  end
end
