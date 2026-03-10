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
      add :encrypted_kek, :binary, null: false
      add :nonce, :binary, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

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
