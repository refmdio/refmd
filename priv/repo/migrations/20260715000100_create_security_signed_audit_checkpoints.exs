defmodule RefMD.Repo.Migrations.CreateSecuritySignedAuditCheckpoints do
  use Ecto.Migration

  def change do
    create table(:security_signed_audit_checkpoints, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :chain_scope_kind, :string, null: false
      add :chain_scope_id, :binary_id, null: false
      add :sequence, :bigint, null: false
      add :event_hash, :string, null: false
      add :previous_signed_checkpoint_sequence, :bigint
      add :previous_signed_checkpoint_hash, :string
      add :signer_user_id, :binary_id, null: false
      add :signer_device_id, :binary_id
      add :signing_key_id, :string, null: false
      add :authorization_checkpoint_sequence, :bigint, null: false
      add :authorization_checkpoint_hash, :string, null: false
      add :covered_event_class, :string, null: false
      add :covered_event_type, :string, null: false
      add :variant, :string, null: false
      add :checkpoint_hash, :string, null: false
      add :payload, :map, null: false
      add :signature, :map, null: false

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(
             :security_signed_audit_checkpoints,
             [:chain_scope_kind, :chain_scope_id, :sequence],
             name: :security_signed_audit_checkpoints_scope_sequence_index
           )

    create unique_index(
             :security_signed_audit_checkpoints,
             [:chain_scope_kind, :chain_scope_id, :checkpoint_hash],
             name: :security_signed_audit_checkpoints_scope_hash_index
           )

    create constraint(
             :security_signed_audit_checkpoints,
             :security_signed_audit_checkpoints_sequence_positive,
             check: "sequence > 0"
           )

    create constraint(
             :security_signed_audit_checkpoints,
             :security_signed_audit_checkpoints_previous_pair,
             check:
               "(sequence = 1 AND previous_signed_checkpoint_sequence IS NULL AND previous_signed_checkpoint_hash IS NULL) OR (sequence > 1 AND previous_signed_checkpoint_sequence IS NOT NULL AND previous_signed_checkpoint_hash IS NOT NULL)"
           )
  end
end
