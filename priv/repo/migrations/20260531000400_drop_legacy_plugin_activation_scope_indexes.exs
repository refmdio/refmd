defmodule RefMD.Repo.Migrations.DropLegacyPluginActivationScopeIndexes do
  use Ecto.Migration

  def up do
    drop_if_exists index(:plugin_activations, [:application_id, :user_id],
                     name: :plugin_activations_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_device_actor_index
                   )
  end

  def down do
    :ok
  end
end
