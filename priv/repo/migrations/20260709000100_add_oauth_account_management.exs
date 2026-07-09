defmodule RefMD.Repo.Migrations.AddOauthAccountManagement do
  use Ecto.Migration

  def up do
    alter table(:oauth_states) do
      add :purpose, :text, null: false, default: "login"
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all)
      add :session_id_hash, :text
    end

    execute("ALTER TABLE oauth_states ALTER COLUMN purpose DROP DEFAULT")

    create index(:oauth_states, [:purpose, :user_id, :expires_at])
    create unique_index(:user_external_accounts, [:user_id, :provider])
  end

  def down do
    drop_if_exists unique_index(:user_external_accounts, [:user_id, :provider])
    drop_if_exists index(:oauth_states, [:purpose, :user_id, :expires_at])

    alter table(:oauth_states) do
      remove :session_id_hash
      remove :user_id
      remove :purpose
    end
  end
end
