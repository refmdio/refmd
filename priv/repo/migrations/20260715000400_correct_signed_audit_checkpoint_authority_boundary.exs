defmodule RefMD.Repo.Migrations.CorrectSignedAuditCheckpointAuthorityBoundary do
  use Ecto.Migration

  def up do
    alter table(:security_signed_audit_checkpoints) do
      add :authorization_checkpoint_scope_kind, :string
      add :authorization_checkpoint_scope_id, :binary_id
    end

    execute("DELETE FROM security_signed_audit_checkpoints")

    alter table(:security_signed_audit_checkpoints) do
      modify :authorization_checkpoint_scope_kind, :string, null: false
      modify :authorization_checkpoint_scope_id, :binary_id, null: false
    end

    drop constraint(
           :security_signed_audit_checkpoints,
           :security_signed_audit_checkpoints_previous_pair
         )

    create constraint(
             :security_signed_audit_checkpoints,
             :security_signed_audit_checkpoints_previous_pair,
             check:
               "(authorization_checkpoint_sequence = 0 AND authorization_checkpoint_hash = 'GENESIS' AND previous_signed_checkpoint_sequence IS NULL AND previous_signed_checkpoint_hash IS NULL) OR (authorization_checkpoint_sequence > 0 AND authorization_checkpoint_hash <> 'GENESIS' AND previous_signed_checkpoint_sequence IS NOT NULL AND previous_signed_checkpoint_hash IS NOT NULL)"
           )

    create constraint(
             :security_signed_audit_checkpoints,
             :security_signed_audit_checkpoints_authority_scope,
             check:
               "authorization_checkpoint_scope_kind = chain_scope_kind AND authorization_checkpoint_scope_id = chain_scope_id"
           )
  end

  def down do
    raise "signed audit checkpoint authority-boundary correction is irreversible"
  end
end
