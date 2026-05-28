defmodule RefMD.Repo.Migrations.MakePluginStorageApplicationScoped do
  use Ecto.Migration

  def up do
    drop_if_exists unique_index(:plugin_kv, [
                     :package_id,
                     :application_id,
                     :activation_id,
                     :scope,
                     :scope_id,
                     :key
                   ])

    execute("""
    DELETE FROM plugin_kv
    WHERE id IN (
      SELECT id
      FROM (
        SELECT id,
               row_number() OVER (
                 PARTITION BY application_id, scope, scope_id, key
                 ORDER BY updated_at DESC, created_at DESC
               ) AS duplicate_rank
        FROM plugin_kv
      ) ranked
      WHERE duplicate_rank > 1
    )
    """)

    create unique_index(:plugin_kv, [:application_id, :scope, :scope_id, :key],
             name: :plugin_kv_application_scope_key_index
           )

    drop_if_exists index(:plugin_records, [
                     :package_id,
                     :application_id,
                     :activation_id,
                     :scope,
                     :scope_id,
                     :kind
                   ])

    create index(:plugin_records, [:application_id, :scope, :scope_id, :kind],
             name: :plugin_records_application_scope_kind_index
           )
  end

  def down do
    drop_if_exists index(:plugin_records, [:application_id, :scope, :scope_id, :kind],
                     name: :plugin_records_application_scope_kind_index
                   )

    create index(:plugin_records, [
             :package_id,
             :application_id,
             :activation_id,
             :scope,
             :scope_id,
             :kind
           ])

    drop_if_exists unique_index(:plugin_kv, [:application_id, :scope, :scope_id, :key],
                     name: :plugin_kv_application_scope_key_index
                   )

    create unique_index(:plugin_kv, [
             :package_id,
             :application_id,
             :activation_id,
             :scope,
             :scope_id,
             :key
           ])
  end
end
