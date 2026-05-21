defmodule RefMD.Repo.Migrations.AddPasswordProtectedShareSupport do
  use Ecto.Migration

  def up do
    alter table(:share_keys) do
      add :salt, :binary
      add :kdf_params, :map
      add :encrypted_auth_key, :binary
      add :auth_key_nonce, :binary
      add :auth_key_server_key_id, :string
    end

    execute(
      "ALTER TABLE share_keys ADD CONSTRAINT share_keys_salt_size CHECK (salt IS NULL OR octet_length(salt) = 16)",
      "ALTER TABLE share_keys DROP CONSTRAINT share_keys_salt_size"
    )

    execute(
      "ALTER TABLE share_keys ADD CONSTRAINT share_keys_auth_key_nonce_size CHECK (auth_key_nonce IS NULL OR octet_length(auth_key_nonce) = 12)",
      "ALTER TABLE share_keys DROP CONSTRAINT share_keys_auth_key_nonce_size"
    )

    create table(:share_password_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all)

      add :token_hash, :string, null: false
      add :challenge, :binary, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:share_password_challenges, [:token_hash])
    create index(:share_password_challenges, [:expires_at])

    execute(
      "ALTER TABLE share_password_challenges ADD CONSTRAINT share_password_challenges_challenge_size CHECK (octet_length(challenge) = 32)",
      "ALTER TABLE share_password_challenges DROP CONSTRAINT share_password_challenges_challenge_size"
    )
  end

  def down do
    drop table(:share_password_challenges)

    execute("ALTER TABLE share_keys DROP CONSTRAINT IF EXISTS share_keys_auth_key_nonce_size")
    execute("ALTER TABLE share_keys DROP CONSTRAINT IF EXISTS share_keys_salt_size")

    alter table(:share_keys) do
      remove :auth_key_server_key_id
      remove :auth_key_nonce
      remove :encrypted_auth_key
      remove :kdf_params
      remove :salt
    end
  end
end
