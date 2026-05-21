defmodule RefMD.Repo.Migrations.AddGuestInvitations do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :account_type, :text, null: false, default: "registered"
    end

    execute(
      "ALTER TABLE users ADD CONSTRAINT users_account_type_check CHECK (account_type IN ('registered', 'guest'))",
      "ALTER TABLE users DROP CONSTRAINT users_account_type_check"
    )

    alter table(:workspaces) do
      add :guest_invites_enabled, :boolean, null: false, default: false
      add :guest_member_limit, :integer
    end

    execute(
      "ALTER TABLE workspaces ADD CONSTRAINT workspaces_guest_member_limit_positive CHECK (guest_member_limit IS NULL OR guest_member_limit > 0)",
      "ALTER TABLE workspaces DROP CONSTRAINT workspaces_guest_member_limit_positive"
    )

    create table(:guest_invitations, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :token_hash, :text, null: false
      add :token_prefix, :text, null: false
      add :scope_kind, :text, null: false
      add :scope_id, :binary_id
      add :permission, :text, null: false
      add :kek_version, :integer, null: false
      add :bootstrap_key_commitment, :text
      add :encrypted_bootstrap_package, :map
      add :bootstrap_package_hash, :text
      add :bootstrap_package_key_recipient_wrap, :map
      add :bootstrap_package_key_maintenance_wrap, :map
      add :bootstrap_suite_id, :text
      add :capability_context_hash, :text
      add :max_redemptions, :integer, null: false, default: 1
      add :redemption_count, :integer, null: false, default: 0
      add :invited_by, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
    end

    create unique_index(:guest_invitations, [:token_hash])
    create index(:guest_invitations, [:workspace_id])
    create index(:guest_invitations, [:scope_id])
    create index(:guest_invitations, [:invited_by])

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_scope_kind_check CHECK (scope_kind IN ('workspace', 'document', 'folder', 'share'))",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_scope_kind_check"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_permission_check CHECK (permission IN ('view', 'edit'))",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_permission_check"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_kek_version_positive CHECK (kek_version > 0)",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_kek_version_positive"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_max_redemptions_positive CHECK (max_redemptions > 0)",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_max_redemptions_positive"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_redemption_count_non_negative CHECK (redemption_count >= 0)",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_redemption_count_non_negative"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_redemption_count_bounded CHECK (redemption_count <= max_redemptions)",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_redemption_count_bounded"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_token_hash_length CHECK (length(token_hash) = 43)",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_token_hash_length"
    )

    execute(
      ~s|ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_token_hash_format CHECK (token_hash ~ '^[A-Za-z0-9\\-_]{43}$')|,
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_token_hash_format"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_token_prefix_length CHECK (length(token_prefix) = 4)",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_token_prefix_length"
    )

    execute(
      ~s|ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_token_prefix_format CHECK (token_prefix ~ '^[A-Za-z0-9\\-_]{4}$')|,
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_token_prefix_format"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_bootstrap_key_commitment_format CHECK (bootstrap_key_commitment IS NULL OR bootstrap_key_commitment ~ '^[A-Za-z0-9\\-_]{43}$')",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_bootstrap_key_commitment_format"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_bootstrap_package_hash_format CHECK (bootstrap_package_hash IS NULL OR bootstrap_package_hash ~ '^[A-Za-z0-9\\-_]{43}$')",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_bootstrap_package_hash_format"
    )

    execute(
      "ALTER TABLE guest_invitations ADD CONSTRAINT guest_invitations_capability_context_hash_format CHECK (capability_context_hash IS NULL OR capability_context_hash ~ '^[A-Za-z0-9\\-_]{43}$')",
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_capability_context_hash_format"
    )

    execute(
      """
      ALTER TABLE guest_invitations
      ADD CONSTRAINT guest_invitations_target_required
      CHECK (
        (scope_kind = 'workspace' AND scope_id IS NULL) OR
        (scope_kind IN ('document', 'folder', 'share') AND scope_id IS NOT NULL)
      )
      """,
      "ALTER TABLE guest_invitations DROP CONSTRAINT guest_invitations_target_required"
    )

    create table(:workspace_guest_grants, primary_key: false) do
      add :id, :binary_id, null: false, default: fragment("gen_random_uuid()")

      add :workspace_id,
          references(:workspaces, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :user_id,
          references(:users, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :scope_kind, :text, null: false
      add :scope_id, :binary_id
      add :permission, :text, null: false

      add :invite_id, references(:guest_invitations, type: :binary_id), null: false

      add :revoked_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:workspace_guest_grants, [:id])
    create index(:workspace_guest_grants, [:user_id])
    create index(:workspace_guest_grants, [:invite_id])
    create index(:workspace_guest_grants, [:workspace_id, :revoked_at])

    execute(
      "ALTER TABLE workspace_guest_grants ADD CONSTRAINT workspace_guest_grants_scope_kind_check CHECK (scope_kind IN ('workspace', 'document', 'folder', 'share'))",
      "ALTER TABLE workspace_guest_grants DROP CONSTRAINT workspace_guest_grants_scope_kind_check"
    )

    execute(
      "ALTER TABLE workspace_guest_grants ADD CONSTRAINT workspace_guest_grants_permission_check CHECK (permission IN ('view', 'edit'))",
      "ALTER TABLE workspace_guest_grants DROP CONSTRAINT workspace_guest_grants_permission_check"
    )

    execute(
      """
      ALTER TABLE workspace_guest_grants
      ADD CONSTRAINT workspace_guest_grants_target_required
      CHECK (
        (scope_kind = 'workspace' AND scope_id IS NULL) OR
        (scope_kind IN ('document', 'folder', 'share') AND scope_id IS NOT NULL)
      )
      """,
      "ALTER TABLE workspace_guest_grants DROP CONSTRAINT workspace_guest_grants_target_required"
    )
  end
end
