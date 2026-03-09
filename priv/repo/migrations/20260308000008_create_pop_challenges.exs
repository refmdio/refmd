defmodule RefMD.Repo.Migrations.CreatePopChallenges do
  use Ecto.Migration

  def change do
    create table(:pop_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all), null: false
      add :challenge_hash, :binary, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:pop_challenges, [:challenge_hash])
    create index(:pop_challenges, [:user_id])
    create index(:pop_challenges, [:expires_at])
  end
end
