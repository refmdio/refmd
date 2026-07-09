defmodule RefMD.Repo.Migrations.CreateRrpChallenges do
  use Ecto.Migration

  def change do
    create table(:rrp_challenges, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :device_id, references(:devices, type: :binary_id, on_delete: :delete_all), null: false
      add :challenge_hash, :binary, null: false
      add :session_id_hash, :string, null: false
      add :session_kind, :string, null: false
      add :subject_id, :binary_id, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:rrp_challenges, [:challenge_hash])
    create index(:rrp_challenges, [:subject_id])
    create index(:rrp_challenges, [:session_id_hash])

    create index(:rrp_challenges, [
             :challenge_hash,
             :session_kind,
             :subject_id,
             :device_id,
             :session_id_hash
           ])

    create index(:rrp_challenges, [:expires_at])

    execute(
      "ALTER TABLE rrp_challenges ADD CONSTRAINT rrp_challenges_session_kind_check CHECK (session_kind = 'user')",
      "ALTER TABLE rrp_challenges DROP CONSTRAINT rrp_challenges_session_kind_check"
    )
  end
end
