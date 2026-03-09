defmodule RefMD.Repo.Migrations.AddPendingDeviceIdToSessions do
  use Ecto.Migration

  def change do
    alter table(:sessions) do
      add :pending_device_id, :binary_id
    end
  end
end
