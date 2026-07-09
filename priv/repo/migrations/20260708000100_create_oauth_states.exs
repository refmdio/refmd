defmodule RefMD.Repo.Migrations.CreateOauthStates do
  use Ecto.Migration

  def change do
    create table(:oauth_states, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :provider, :text, null: false
      add :state_hash, :binary, null: false
      add :nonce, :text, null: false
      add :code_verifier, :text, null: false
      add :redirect_uri, :text, null: false
      add :return_to, :text, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :consumed_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:oauth_states, [:state_hash])
    create index(:oauth_states, [:provider, :expires_at])
    create index(:oauth_states, [:consumed_at])
  end
end
