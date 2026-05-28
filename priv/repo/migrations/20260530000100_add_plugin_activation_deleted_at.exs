defmodule RefMD.Repo.Migrations.AddPluginActivationDeletedAt do
  use Ecto.Migration

  def up do
    alter table(:plugin_activations) do
      add :deleted_at, :utc_datetime_usec
    end

    drop_if_exists index(:plugin_activations, [:application_id, :user_id],
                     name: :plugin_activations_application_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_application_device_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id],
                     name: :plugin_activations_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_device_actor_index
                   )

    create unique_index(:plugin_activations, [:application_id, :user_id],
             name: :plugin_activations_application_user_actor_index,
             where: "activation_scope_kind = 'user' AND deleted_at IS NULL"
           )

    create unique_index(:plugin_activations, [:application_id, :user_id, :device_id],
             name: :plugin_activations_application_device_actor_index,
             where: "activation_scope_kind = 'device' AND deleted_at IS NULL"
           )
  end

  def down do
    drop_if_exists index(:plugin_activations, [:application_id, :user_id],
                     name: :plugin_activations_application_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_application_device_actor_index
                   )

    create unique_index(:plugin_activations, [:application_id, :user_id],
             name: :plugin_activations_application_user_actor_index,
             where: "activation_scope_kind = 'user'"
           )

    create unique_index(:plugin_activations, [:application_id, :user_id, :device_id],
             name: :plugin_activations_application_device_actor_index,
             where: "activation_scope_kind = 'device'"
           )

    alter table(:plugin_activations) do
      remove :deleted_at
    end
  end
end
