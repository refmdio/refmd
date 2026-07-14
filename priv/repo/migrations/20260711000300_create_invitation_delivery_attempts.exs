defmodule RefMD.Repo.Migrations.CreateInvitationDeliveryAttempts do
  use Ecto.Migration

  def change do
    create table(:invitation_delivery_attempts, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :workspace_id, references(:workspaces, type: :uuid, on_delete: :delete_all), null: false
      add :context_kind, :string, null: false
      add :context_id, :uuid, null: false
      add :recipient_user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false

      add :recipient_device_id, references(:devices, type: :uuid, on_delete: :delete_all),
        null: false

      add :target_user_id, :uuid, null: false
      add :target_device_id, :uuid, null: false
      add :target_encryption_key_id, :string, null: false
      add :target_key_checkpoint_sequence, :bigint
      add :target_key_checkpoint_hash, :string
      add :target_registration, :map, null: false
      add :target_registration_proof, :map
      add :recipient_redeem_nonce, :string, null: false
      add :live_redeem_challenge_hash, :string, null: false
      add :recipient_nonce_state_hash, :string, null: false
      add :request_binding_hash, :string, null: false
      add :resource_hash, :string, null: false
      add :context_snapshot, :map, null: false
      add :status, :string, null: false, default: "pending"
      add :authorization_id, :uuid
      add :approved_artifacts, :map
      add :expires_at, :utc_datetime_usec, null: false
      add :approved_at, :utc_datetime_usec
      add :consumed_at, :utc_datetime_usec
      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: :updated_at)
    end

    create index(:invitation_delivery_attempts, [:workspace_id, :status])
    create index(:invitation_delivery_attempts, [:context_kind, :context_id, :status])
    create index(:invitation_delivery_attempts, [:recipient_user_id, :recipient_device_id])

    create unique_index(:invitation_delivery_attempts, [:authorization_id],
             where: "authorization_id IS NOT NULL"
           )

    create constraint(:invitation_delivery_attempts, :invitation_delivery_attempt_context,
             check: "context_kind IN ('workspace_invitation', 'guest_invitation')"
           )

    create constraint(:invitation_delivery_attempts, :invitation_delivery_attempt_status,
             check: "status IN ('pending', 'approved', 'consumed', 'expired')"
           )
  end
end
