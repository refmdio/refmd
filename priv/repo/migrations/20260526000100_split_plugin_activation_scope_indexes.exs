defmodule RefMD.Repo.Migrations.SplitPluginActivationScopeIndexes do
  use Ecto.Migration

  def up do
    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_actor_index
                   )

    create unique_index(:plugin_activations, [:application_id, :user_id],
             name: :plugin_activations_user_actor_index,
             where: "activation_scope_kind = 'user'"
           )

    create unique_index(:plugin_activations, [:application_id, :user_id, :device_id],
             name: :plugin_activations_device_actor_index,
             where: "activation_scope_kind = 'device'"
           )
  end

  def down do
    drop_if_exists index(:plugin_activations, [:application_id, :user_id],
                     name: :plugin_activations_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_device_actor_index
                   )

    create unique_index(:plugin_activations, [:application_id, :user_id, :device_id],
             name: :plugin_activations_actor_index
           )
  end
end
