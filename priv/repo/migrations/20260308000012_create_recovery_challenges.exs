defmodule RefMD.Repo.Migrations.CreateRecoveryChallenges do
  use Ecto.Migration

  def change do
    create table(:recovery_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :challenge_hash, :binary, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:recovery_challenges, [:challenge_hash])
    create index(:recovery_challenges, [:user_id])
  end
end
