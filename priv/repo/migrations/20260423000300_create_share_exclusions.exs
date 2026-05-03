defmodule RefMD.Repo.Migrations.CreateShareExclusions do
  use Ecto.Migration

  def change do
    create table(:share_exclusions, primary_key: false) do
      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create index(:share_exclusions, [:document_id])
  end
end
