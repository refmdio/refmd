defmodule RefMD.Repo.Migrations.CreateAccounts do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :text, null: false
      add :name, :text, null: false
      add :encryption_setup_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create unique_index(:users, [:email])

    create table(:user_settings, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        primary_key: true

      add :theme, :text, null: false, default: "system"
      add :locale, :text, null: false, default: "en"
      add :editor_vim_mode, :boolean, null: false, default: false
      add :editor_font_size, :integer, null: false, default: 14

      add :updated_at, :utc_datetime_usec, null: false
    end

    create table(:user_external_accounts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :provider, :text, null: false
      add :provider_user_id, :text, null: false
      add :email, :text

      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:user_external_accounts, [:provider, :provider_user_id])
    create index(:user_external_accounts, [:user_id])

    create table(:user_shortcuts, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :action, :text, null: false
      add :keys, :text, null: false

      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:user_shortcuts, [:user_id, :action])

    create table(:devices, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :name, :text, null: false
      add :device_type, :text, null: false
      add :ecdh_public_key, :binary, null: false
      add :signing_public_key, :binary, null: false
      add :identity_signature, :binary, null: false
      add :client_nonce, :binary, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
    end

    create index(:devices, [:user_id])
    create unique_index(:devices, [:signing_public_key])
    create unique_index(:devices, [:ecdh_public_key])

    create table(:sessions, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :device_id, references(:devices, type: :binary_id, on_delete: :nilify_all)
      add :token_hash, :text, null: false
      add :remember_me, :boolean, null: false
      add :is_recovery, :boolean, null: false, default: false
      add :ip_address, :text
      add :user_agent, :text
      add :expires_at, :utc_datetime_usec, null: false
      add :last_seen_at, :utc_datetime_usec, null: false
      add :last_verified_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create index(:sessions, [:user_id])
    create unique_index(:sessions, [:token_hash])

    create table(:device_registrations, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :name, :text, null: false
      add :device_type, :text, null: false
      add :ecdh_public_key, :binary, null: false
      add :signing_public_key, :binary, null: false
      add :client_nonce, :binary, null: false
      add :ip_address, :text
      add :created_at, :utc_datetime_usec, null: false
      add :expires_at, :utc_datetime_usec, null: false
    end

    create index(:device_registrations, [:user_id])
  end
end
