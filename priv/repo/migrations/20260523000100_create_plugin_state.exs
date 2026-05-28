defmodule RefMD.Repo.Migrations.CreatePluginState do
  use Ecto.Migration

  def change do
    create table(:plugin_packages, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :plugin_id, :text, null: false
      add :version, :text, null: false
      add :owner_scope_kind, :text, null: false
      add :owner_workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all)
      add :owner_user_id, references(:users, type: :binary_id, on_delete: :delete_all)
      add :created_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :created_by_device_id, references(:devices, type: :binary_id, on_delete: :nilify_all)
      add :bundle_hash, :text, null: false
      add :resource_manifest_hash, :text, null: false
      add :state_head_hash, :text, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create index(:plugin_packages, [:owner_user_id])
    create index(:plugin_packages, [:owner_workspace_id])

    create unique_index(
             :plugin_packages,
             [:owner_scope_kind, :owner_workspace_id, :plugin_id, :version, :bundle_hash],
             name: :plugin_packages_workspace_owner_package_index,
             where: "owner_scope_kind = 'workspace'"
           )

    create unique_index(
             :plugin_packages,
             [:owner_scope_kind, :owner_user_id, :plugin_id, :version, :bundle_hash],
             name: :plugin_packages_user_owner_package_index,
             where: "owner_scope_kind = 'user'"
           )

    create constraint(:plugin_packages, :plugin_packages_owner_scope_check,
             check: """
             (owner_scope_kind = 'workspace' AND owner_workspace_id IS NOT NULL AND owner_user_id IS NULL)
             OR (owner_scope_kind = 'user' AND owner_workspace_id IS NULL AND owner_user_id IS NOT NULL)
             """
           )

    create table(:plugin_applications, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :package_id, references(:plugin_packages, type: :binary_id, on_delete: :delete_all),
        null: false

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :plugin_id, :text, null: false
      add :application_scope_kind, :text, null: false, default: "workspace"
      add :application_mode, :text, null: false
      add :workspace_policy_result, :text, null: false, default: "allowed"
      add :config, :map
      add :created_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :enabled, :boolean, null: false, default: true
      add :consent_epoch, :integer, null: false, default: 0
      add :state_head_hash, :text, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:plugin_applications, [:workspace_id, :package_id])
    create index(:plugin_applications, [:workspace_id, :enabled])

    create constraint(:plugin_applications, :plugin_applications_scope_check,
             check: "application_scope_kind = 'workspace'"
           )

    create constraint(:plugin_applications, :plugin_applications_mode_check,
             check: "application_mode IN ('workspace_shared', 'user_applied')"
           )

    create constraint(:plugin_applications, :plugin_applications_policy_check,
             check: "workspace_policy_result IN ('allowed', 'denied', 'needs_admin_review')"
           )

    create table(:plugin_activations, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :application_id,
          references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
          null: false

      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all)
      add :activation_scope_kind, :text, null: false
      add :enabled, :boolean, null: false, default: true

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
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

    create table(:plugin_bundles, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :package_id, references(:plugin_packages, type: :binary_id, on_delete: :delete_all),
        null: false

      add :application_id,
          references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
          null: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: true

      add :plugin_id, :text, null: false
      add :version, :text, null: false
      add :bundle_hash, :text, null: false
      add :manifest_hash, :text, null: false
      add :resource_manifest, {:array, :map}, null: false, default: []
      add :resource_manifest_hash, :text, null: false
      add :permissions_hash, :text, null: false
      add :endpoint_hash, :text, null: false
      add :document_scope_hash, :text, null: false
      add :approval_event_hash, :text, null: false
      add :approved_by_user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :approved_by_device_id, references(:devices, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create index(:plugin_bundles, [:workspace_id])
    create unique_index(:plugin_bundles, [:package_id, :bundle_hash])
    create unique_index(:plugin_bundles, [:application_id, :bundle_hash])
    create unique_index(:plugin_bundles, [:application_id, :approval_event_hash])

    alter table(:plugin_packages) do
      add :current_bundle_id,
          references(:plugin_bundles, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:plugin_applications) do
      add :current_bundle_id,
          references(:plugin_bundles, type: :binary_id, on_delete: :nilify_all)
    end

    create table(:plugin_kv, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :application_id,
          references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
          null: false

      add :package_id, references(:plugin_packages, type: :binary_id, on_delete: :delete_all),
        null: false

      add :activation_id,
          references(:plugin_activations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :plugin_id, :text, null: false
      add :scope, :text, null: false
      add :scope_id, :text, null: false
      add :key, :text, null: false
      add :ciphertext, :binary, null: false
      add :nonce, :binary, null: false
      add :key_version, :integer, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:plugin_kv, [
             :package_id,
             :application_id,
             :activation_id,
             :scope,
             :scope_id,
             :key
           ])

    create constraint(:plugin_kv, :plugin_kv_scope_check,
             check: "scope IN ('document', 'workspace')"
           )

    create table(:plugin_records, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :application_id,
          references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
          null: false

      add :package_id, references(:plugin_packages, type: :binary_id, on_delete: :delete_all),
        null: false

      add :activation_id,
          references(:plugin_activations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :plugin_id, :text, null: false
      add :scope, :text, null: false
      add :scope_id, :text, null: false
      add :kind, :text, null: false
      add :encrypted_data, :binary, null: false
      add :nonce, :binary, null: false
      add :key_version, :integer, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create index(:plugin_records, [
             :package_id,
             :application_id,
             :activation_id,
             :scope,
             :scope_id,
             :kind
           ])

    create constraint(:plugin_records, :plugin_records_scope_check,
             check: "scope IN ('document', 'workspace')"
           )

    create table(:plugin_consent_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :plugin_id, :text, null: false

      add :package_id, references(:plugin_packages, type: :binary_id, on_delete: :delete_all),
        null: false

      add :application_id,
          references(:plugin_applications, type: :binary_id, on_delete: :delete_all),
          null: false

      add :activation_id,
          references(:plugin_activations, type: :binary_id, on_delete: :delete_all),
          null: false

      add :owner_scope_kind, :text, null: false
      add :application_scope_kind, :text, null: false
      add :version, :text, null: false
      add :bundle_hash, :text, null: false
      add :manifest_hash, :text, null: false
      add :resource_manifest_hash, :text, null: false
      add :permissions_hash, :text, null: false
      add :endpoint_hash, :text, null: false
      add :document_scope_hash, :text, null: false

      add :signer_device_id, references(:devices, type: :binary_id, on_delete: :restrict),
        null: false

      add :signer_user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :user_id, references(:users, type: :binary_id, on_delete: :restrict), null: false
      add :device_id, references(:devices, type: :binary_id, on_delete: :restrict), null: false

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :decision, :text, null: false
      add :consent_epoch, :integer, null: false
      add :previous_event_hash, :text, null: false
      add :event_hash, :text, null: false
      add :hybrid_signature, :map, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create index(:plugin_consent_events, [:workspace_id])
    create index(:plugin_consent_events, [:application_id, :user_id, :device_id])

    create unique_index(
             :plugin_consent_events,
             [:application_id, :user_id, :device_id, :consent_epoch],
             name: :plugin_consent_events_actor_epoch_index
           )

    create unique_index(:plugin_consent_events, [:application_id, :event_hash])

    create constraint(:plugin_consent_events, :plugin_consent_events_decision_check,
             check: "decision IN ('allow', 'deny', 'revoke')"
           )
  end
end
