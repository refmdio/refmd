defmodule RefMD.Repo.Migrations.CreateDocuments do
  use Ecto.Migration

  def change do
    create table(:documents, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :parent_id, references(:documents, type: :binary_id, on_delete: :nothing)
      add :position, :integer, null: false, default: 0
      add :title, :text, null: false, default: "Untitled"
      add :encrypted_title, :binary
      add :encrypted_title_nonce, :binary
      add :encrypted_title_key_version, :integer
      add :slug, :text, null: false
      add :path, :text
      add :doc_type, :text, null: false, default: "document"
      add :is_encrypted, :boolean, null: false, default: true
      add :needs_dek_rotation, :boolean, null: false, default: false
      add :needs_rotation_snapshot, :boolean, null: false, default: false
      add :min_dek_version, :integer, null: false, default: 1
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :archived_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    # active_snapshot_id added after document_snapshots table is created
    create index(:documents, [:workspace_id])

    create unique_index(:documents, [:workspace_id, :parent_id, :position],
             name: :documents_workspace_parent_position,
             nulls_distinct: false
           )

    create table(:document_snapshots, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        null: false

      add :parent_snapshot_id, references(:document_snapshots, type: :binary_id)
      add :latest_version, :bigint, null: false, default: 0
      add :data, :binary, null: false
      add :nonce, :binary, null: false
      add :key_version, :integer, null: false
      add :hybrid_signature, :map, null: false
      add :ciphertext_hash, :text, null: false
      add :snapshot_signature_hash, :text, null: false
      add :snapshot_admission_event_hash, :text, null: false
      add :proof_chain_hash, :text, null: false
      add :clocks, :map, null: false, default: %{}
      add :parent_snapshot_update_clocks, :map, null: false, default: %{}
      add :parent_proof_hash, :text, null: false, default: "GENESIS"
      add :created_by_signing_key_id, :text, null: false
      add :owner_kind, :text, null: false
      add :owner_id, :text, null: false
      add :authority_kind, :text, null: false
      add :authority_id, :text, null: false
      add :authority_context_key, :text, null: false
      add :authority_scope_id, :text, null: false
      add :authority_permission_version, :integer, null: false
      add :key_checkpoint_sequence, :bigint, null: false
      add :key_checkpoint_hash, :text, null: false
      add :created_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    create index(:document_snapshots, [:document_id])

    # Add active_snapshot_id FK to documents
    alter table(:documents) do
      add :active_snapshot_id, references(:document_snapshots, type: :binary_id)
    end

    create table(:document_updates, primary_key: false) do
      add :id, :bigserial, primary_key: true

      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        null: false

      add :snapshot_id, references(:document_snapshots, type: :binary_id), null: false
      add :clock, :integer, null: false
      add :version, :bigint, null: false
      add :signing_key_id, :text, null: false
      add :update_data, :binary, null: false
      add :nonce, :binary, null: false
      add :key_version, :integer, null: false
      add :update_hash, :text, null: false
      add :hybrid_signature, :map, null: false
      add :owner_kind, :text, null: false
      add :owner_id, :text, null: false
      add :authority_kind, :text, null: false
      add :authority_id, :text, null: false
      add :authority_context_key, :text, null: false
      add :authority_scope_id, :text, null: false
      add :authority_permission_version, :integer, null: false
      add :key_checkpoint_sequence, :bigint, null: false
      add :key_checkpoint_hash, :text, null: false
      add :admission_event_hash, :text, null: false
      add :timestamp, :bigint, null: false
      add :created_at, :utc_datetime_usec, null: false, default: fragment("NOW()")
    end

    create index(:document_updates, [:snapshot_id])
    create unique_index(:document_updates, [:document_id, :version])
    create unique_index(:document_updates, [:document_id, :update_hash])

    # CHECK: all persisted updates use the signed owner-authenticated shape.
    execute(
      """
      ALTER TABLE document_updates
      ADD CONSTRAINT document_updates_auth_check
      CHECK (
        hybrid_signature IS NOT NULL AND
        clock IS NOT NULL AND
        signing_key_id IS NOT NULL AND
        owner_kind IS NOT NULL AND
        owner_id IS NOT NULL AND
        authority_kind IS NOT NULL AND
        authority_id IS NOT NULL AND
        authority_context_key IS NOT NULL AND
        authority_scope_id IS NOT NULL AND
        authority_permission_version IS NOT NULL AND
        key_checkpoint_sequence IS NOT NULL AND
        key_checkpoint_hash IS NOT NULL AND
        admission_event_hash IS NOT NULL
      )
      """,
      """
      ALTER TABLE document_updates
      DROP CONSTRAINT document_updates_auth_check
      """
    )

    create table(:document_snapshot_archives, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        null: false

      add :snapshot_id, references(:document_snapshots, type: :binary_id, on_delete: :delete_all),
        null: false

      add :label, :text, null: false
      add :notes, :text
      add :kind, :text, null: false
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:document_snapshot_archives, [:document_id])
  end
end
