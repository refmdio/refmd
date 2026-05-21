defmodule RefMD.Repo.Migrations.CreateWorkspaceMemberEnvelopes do
  use Ecto.Migration

  def change do
    create table(:workspace_member_envelopes, primary_key: false) do
      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :target_user_id, :binary_id, null: false, primary_key: true
      add :key_version, :integer, null: false, primary_key: true
      add :sender_device_id, :binary_id, null: false
      add :wrap_protocol, :text, null: false
      add :wrap_version, :integer, null: false
      add :suite_id, :text, null: false
      add :suite_rank, :integer, null: false
      add :purpose, :text, null: false
      add :resource, :map, null: false
      add :sender, :map, null: false
      add :recipient, :map, null: false
      add :event_scope, :map, null: false
      add :wrap_event_sequence, :bigint, null: false
      add :wrap_event_hash, :binary, null: false
      add :wrap_event_body_hash, :binary, null: false
      add :operation_checkpoint_sequence, :bigint, null: false
      add :operation_checkpoint_hash, :binary, null: false
      add :operation_checkpoint_covered_head_sequence, :bigint, null: false
      add :operation_checkpoint_covered_head_hash, :binary, null: false
      add :wrap_body_hash, :binary, null: false
      add :recipient_key_id, :binary, null: false
      add :sender_signing_key_id, :binary, null: false
      add :hpke_enc, :binary, null: false
      add :hpke_ciphertext, :binary, null: false
      add :signature_protocol, :text, null: false
      add :signature_version, :integer, null: false
      add :signature_suite_id, :text, null: false
      add :signature_suite_rank, :integer, null: false
      add :transcript_hash, :binary, null: false
      add :ed25519_signature, :binary, null: false
      add :mldsa65_signature, :binary, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:workspace_member_envelopes, [:suite_id])
    create index(:workspace_member_envelopes, [:sender_signing_key_id])
    create index(:workspace_member_envelopes, [:recipient_key_id])

    # Composite FK: (workspace_id, target_user_id) → workspace_members(workspace_id, user_id)
    execute(
      """
      ALTER TABLE workspace_member_envelopes
      ADD CONSTRAINT workspace_member_envelopes_member_fk
      FOREIGN KEY (workspace_id, target_user_id)
      REFERENCES workspace_members (workspace_id, user_id)
      ON DELETE CASCADE
      """,
      """
      ALTER TABLE workspace_member_envelopes
      DROP CONSTRAINT workspace_member_envelopes_member_fk
      """
    )
  end
end
