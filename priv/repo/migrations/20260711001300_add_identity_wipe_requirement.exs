defmodule RefMD.Repo.Migrations.AddIdentityWipeRequirement do
  use Ecto.Migration

  def change do
    alter table(:devices) do
      add :identity_wipe_required_at, :utc_datetime_usec

      add :identity_replaced_by_device_id,
          references(:devices, type: :binary_id, on_delete: :nilify_all)
    end

    alter table(:sessions) do
      add :identity_recovery_required, :boolean, null: false, default: false
    end
  end
end
