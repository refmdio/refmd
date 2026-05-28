defmodule RefMD.Repo.Migrations.AddPluginArtifactCandidates do
  use Ecto.Migration

  def change do
    create table(:plugin_bundle_candidates, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all)

      add :application_id,
          references(:plugin_applications, type: :binary_id, on_delete: :nilify_all)

      add :package_id, :binary_id, null: false
      add :owner_scope_kind, :text, null: false
      add :owner_workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all)
      add :owner_user_id, references(:users, type: :binary_id, on_delete: :delete_all)
      add :plugin_id, :text, null: false
      add :version, :text, null: false
      add :source_kind, :text, null: false
      add :source_url, :text
      add :source_url_hash, :text, null: false
      add :archive_hash, :text, null: false
      add :manifest_json, :map, null: false
      add :manifest_hash, :text, null: false
      add :main_js_hash, :text, null: false
      add :styles_css_hash, :text, null: false
      add :resource_manifest, {:array, :map}, null: false, default: []
      add :resource_manifest_hash, :text, null: false
      add :bundle_hash, :text, null: false
      add :permissions_hash, :text, null: false
      add :endpoint_hash, :text, null: false
      add :renderer_slots_hash, :text, null: false
      add :document_scope_hash, :text, null: false
      add :validation_status, :text, null: false
      add :validation_errors, {:array, :text}, null: false, default: []
      add :created_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :created_by_device_id, references(:devices, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create index(:plugin_bundle_candidates, [:workspace_id])
    create index(:plugin_bundle_candidates, [:application_id])

    create unique_index(
             :plugin_bundle_candidates,
             [:owner_scope_kind, :owner_workspace_id, :owner_user_id, :plugin_id, :archive_hash],
             name: :plugin_bundle_candidates_owner_archive_index
           )

    create constraint(:plugin_bundle_candidates, :plugin_bundle_candidates_owner_scope_check,
             check: """
             (owner_scope_kind = 'workspace' AND owner_workspace_id IS NOT NULL AND owner_user_id IS NULL)
             OR (owner_scope_kind = 'user' AND owner_workspace_id IS NULL AND owner_user_id IS NOT NULL)
             """
           )

    create constraint(:plugin_bundle_candidates, :plugin_bundle_candidates_source_kind_check,
             check: "source_kind IN ('remote_https_url', 'local_upload')"
           )

    create constraint(
             :plugin_bundle_candidates,
             :plugin_bundle_candidates_validation_status_check,
             check: "validation_status IN ('valid', 'invalid')"
           )

    alter table(:plugin_bundles) do
      add :candidate_id,
          references(:plugin_bundle_candidates, type: :binary_id, on_delete: :restrict),
          null: false

      add :source_kind, :text
      add :source_url_hash, :text
      add :archive_hash, :text
      add :manifest_json, :map, null: false
      add :main_js_hash, :text
      add :styles_css_hash, :text
      add :renderer_slots_hash, :text
      add :approval_epoch, :integer
      add :previous_approval_event_hash, :text
      add :hybrid_signature, :map
      add :approved_at_ms, :bigint
    end

    create index(:plugin_bundles, [:candidate_id])

    create constraint(:plugin_bundles, :plugin_bundles_source_kind_check,
             check: "source_kind IS NULL OR source_kind IN ('remote_https_url', 'local_upload')"
           )

    create table(:plugin_package_entries, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :owner_scope_kind, :text, null: false
      add :owner_workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all)
      add :owner_user_id, references(:users, type: :binary_id, on_delete: :delete_all)

      add :candidate_id,
          references(:plugin_bundle_candidates, type: :binary_id, on_delete: :delete_all)

      add :bundle_id, references(:plugin_bundles, type: :binary_id, on_delete: :delete_all)
      add :package_id, references(:plugin_packages, type: :binary_id, on_delete: :delete_all)
      add :entry_kind, :text, null: false
      add :logical_path, :text, null: false
      add :resource_kind, :text
      add :media_type, :text, null: false
      add :byte_length, :integer, null: false
      add :hash, :text, null: false
      add :storage_path, :text, null: false
      add :status, :text, null: false
      add :pinned_at, :utc_datetime_usec
      add :deleted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create unique_index(:plugin_package_entries, [:storage_path])
    create unique_index(:plugin_package_entries, [:candidate_id, :logical_path])
    create unique_index(:plugin_package_entries, [:bundle_id, :logical_path])

    create unique_index(:plugin_package_entries, [:candidate_id, :entry_kind],
             name: :plugin_package_entries_candidate_singleton_kind_index,
             where:
               "candidate_id IS NOT NULL AND entry_kind IN ('manifest', 'main_js', 'styles_css')"
           )

    create unique_index(:plugin_package_entries, [:bundle_id, :entry_kind],
             name: :plugin_package_entries_bundle_singleton_kind_index,
             where:
               "bundle_id IS NOT NULL AND entry_kind IN ('manifest', 'main_js', 'styles_css')"
           )

    create constraint(:plugin_package_entries, :plugin_package_entries_owner_scope_check,
             check: """
             (owner_scope_kind = 'workspace' AND owner_workspace_id IS NOT NULL AND owner_user_id IS NULL)
             OR (owner_scope_kind = 'user' AND owner_workspace_id IS NULL AND owner_user_id IS NOT NULL)
             """
           )

    create constraint(:plugin_package_entries, :plugin_package_entries_kind_check,
             check: "entry_kind IN ('manifest', 'main_js', 'styles_css', 'resource')"
           )

    create constraint(:plugin_package_entries, :plugin_package_entries_kind_path_check,
             check: """
             (entry_kind = 'manifest' AND logical_path = 'manifest.json' AND resource_kind IS NULL)
             OR (entry_kind = 'main_js' AND logical_path = 'main.js' AND resource_kind IS NULL)
             OR (entry_kind = 'styles_css' AND logical_path = 'styles.css' AND resource_kind IS NULL)
             OR (entry_kind = 'resource' AND logical_path LIKE 'resources/%' AND length(logical_path) > length('resources/') AND resource_kind IS NOT NULL)
             """
           )

    create constraint(:plugin_package_entries, :plugin_package_entries_status_check,
             check: "status IN ('candidate', 'pinned', 'rejected', 'orphan_pending_delete')"
           )

    create constraint(:plugin_package_entries, :plugin_package_entries_storage_path_id_check,
             check: "storage_path = 'plugin-packages/' || id::text"
           )
  end
end
