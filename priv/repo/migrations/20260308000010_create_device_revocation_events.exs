defmodule RefMD.Repo.Migrations.CreateDeviceRevocationEvents do
  use Ecto.Migration

  def change do
    create table(:device_revocation_events, primary_key: false) do
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        null: false,
        primary_key: true

      add :device_id, :binary_id, null: false, primary_key: true
      add :revoked_by_device_id, :binary_id, null: false
      add :revocation_mode, :text, null: false
      add :signature, :binary, null: false
      add :revoked_at, :bigint, null: false
      add :created_at, :utc_datetime_usec, null: false
    end
  end
end
