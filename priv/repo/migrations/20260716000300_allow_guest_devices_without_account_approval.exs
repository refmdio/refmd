defmodule RefMD.Repo.Migrations.AllowGuestDevicesWithoutAccountApproval do
  use Ecto.Migration

  def up do
    alter table(:devices) do
      modify :approval_signature, :map, null: true
      modify :approval_signature_surface, :text, null: true
      modify :approval_proof, :map, null: true
    end

    alter table(:user_identity_public_keys) do
      modify :pending_registration_challenge_hash, :text, null: true
    end
  end
end
