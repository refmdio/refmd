defmodule RefMD.Repo.Migrations.RemovePluginActivationPackageTarget do
  use Ecto.Migration

  def change do
    drop_if_exists constraint(:plugin_activations, :plugin_activations_scope_check)

    drop_if_exists index(:plugin_activations, [:package_id, :user_id],
                     name: :plugin_activations_package_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:package_id, :user_id, :device_id],
                     name: :plugin_activations_package_device_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:package_id, :user_id, :device_id],
                     name: :plugin_activations_package_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id],
                     name: :plugin_activations_application_user_actor_index
                   )

    drop_if_exists index(:plugin_activations, [:application_id, :user_id, :device_id],
                     name: :plugin_activations_application_device_actor_index
                   )

    execute """
            DELETE FROM plugin_activations
            WHERE application_id IS NULL
            """,
            "SELECT 1"

    execute """
            ALTER TABLE plugin_activations
              DROP CONSTRAINT IF EXISTS plugin_activations_package_id_fkey
            """,
            """
            ALTER TABLE plugin_activations
              ADD CONSTRAINT plugin_activations_package_id_fkey
              FOREIGN KEY (package_id)
              REFERENCES plugin_packages(id)
              ON DELETE CASCADE
            """

    execute """
            ALTER TABLE plugin_activations
              DROP COLUMN IF EXISTS package_id
            """,
            """
            ALTER TABLE plugin_activations
              ADD COLUMN package_id uuid
            """

    alter table(:plugin_activations) do
      modify :application_id,
             references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
             null: false,
             from: {
               references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
               null: true
             }
    end

    create unique_index(:plugin_activations, [:application_id, :user_id],
             name: :plugin_activations_application_user_actor_index,
             where: "activation_scope_kind = 'user'"
           )

    create unique_index(:plugin_activations, [:application_id, :user_id, :device_id],
             name: :plugin_activations_application_device_actor_index,
             where: "activation_scope_kind = 'device'"
           )

    create constraint(:plugin_activations, :plugin_activations_scope_check,
             check: """
             ((activation_scope_kind = 'device' AND device_id IS NOT NULL)
              OR (activation_scope_kind = 'user' AND device_id IS NULL))
             """
           )
  end
end
