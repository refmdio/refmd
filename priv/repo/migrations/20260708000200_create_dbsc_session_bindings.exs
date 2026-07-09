defmodule RefMD.Repo.Migrations.CreateDbscSessionBindings do
  use Ecto.Migration

  def change do
    create table(:dbsc_session_bindings, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :session_kind, :text, null: false
      add :session_id, :binary_id, null: false
      add :session_identifier, :text, null: false
      add :public_key_jwk, :map, null: false
      add :current_token_hash, :text
      add :current_challenge, :text, null: false
      add :previous_challenge, :text
      add :previous_challenge_expires_at, :utc_datetime_usec
      add :binding_expires_at, :utc_datetime_usec, null: false
      add :credential_expires_at, :utc_datetime_usec
      add :last_verified_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
      add :updated_at, :utc_datetime_usec, null: false
    end

    create unique_index(:dbsc_session_bindings, [:session_kind, :session_id])
    create unique_index(:dbsc_session_bindings, [:session_identifier])
    create index(:dbsc_session_bindings, [:session_kind, :session_id, :binding_expires_at])
    create index(:dbsc_session_bindings, [:credential_expires_at])

    create constraint(:dbsc_session_bindings, :dbsc_session_kind_check,
             check: "session_kind in ('user', 'share_participant', 'mount')"
           )
  end
end
