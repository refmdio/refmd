defmodule RefMD.Repo.Migrations.AddPluginUserPolicyToWorkspaces do
  use Ecto.Migration

  def change do
    alter table(:workspaces) do
      add :plugin_user_policy, :map
    end
  end
end
