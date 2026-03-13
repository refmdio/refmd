defmodule RefMD.Repo.Migrations.CreateWorkspaceInvitations do
  use Ecto.Migration

  def change do
    create table(:workspace_invitations, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :token_hash, :text, null: false
      add :token_prefix, :text, null: false

      add :role_id, :binary_id

      add :invited_by, references(:users, type: :binary_id), null: false
      add :invited_email, :text, null: false

      add :encrypted_kek, :bytea, null: false
      add :kek_nonce, :bytea, null: false
      add :kek_version, :integer, null: false

      add :is_used, :boolean, null: false, default: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
    end

    create unique_index(:workspace_invitations, [:token_hash])

    # Composite FK: (workspace_id, role_id) → workspace_roles(workspace_id, id)
    # SET NULL on role deletion
    execute(
      """
      ALTER TABLE workspace_invitations
      ADD CONSTRAINT workspace_invitations_role_fk
      FOREIGN KEY (workspace_id, role_id)
      REFERENCES workspace_roles (workspace_id, id)
      ON DELETE SET NULL (role_id)
      """,
      """
      ALTER TABLE workspace_invitations
      DROP CONSTRAINT workspace_invitations_role_fk
      """
    )

    # CHECK constraints
    execute(
      "ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_encrypted_kek_length CHECK (length(encrypted_kek) = 48)",
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_encrypted_kek_length"
    )

    execute(
      "ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_kek_nonce_length CHECK (length(kek_nonce) = 24)",
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_kek_nonce_length"
    )

    execute(
      "ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_kek_version_positive CHECK (kek_version > 0)",
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_kek_version_positive"
    )

    execute(
      "ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_token_hash_length CHECK (length(token_hash) = 43)",
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_token_hash_length"
    )

    execute(
      ~s|ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_token_hash_format CHECK (token_hash ~ '^[A-Za-z0-9\\-_]{43}$')|,
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_token_hash_format"
    )

    execute(
      "ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_token_prefix_length CHECK (length(token_prefix) = 4)",
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_token_prefix_length"
    )

    execute(
      ~s|ALTER TABLE workspace_invitations ADD CONSTRAINT invitation_token_prefix_format CHECK (token_prefix ~ '^[A-Za-z0-9\\-_]{4}$')|,
      "ALTER TABLE workspace_invitations DROP CONSTRAINT invitation_token_prefix_format"
    )
  end
end
