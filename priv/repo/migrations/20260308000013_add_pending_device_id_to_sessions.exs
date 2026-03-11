defmodule RefMD.Repo.Migrations.AddDeviceRegistrationIdToSessions do
  use Ecto.Migration

  def change do
    alter table(:sessions) do
      add :device_registration_id,
          references(:device_registrations, type: :binary_id, on_delete: :nilify_all)
    end
  end
end
