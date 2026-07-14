defmodule RefMD.Repo.Migrations.AddSecurityAuditHashChain do
  use Ecto.Migration

  def up do
    execute("DELETE FROM security_audit_events")

    alter table(:security_audit_events) do
      add :chain_scope, :text, null: false
      add :sequence, :bigint, null: false
      add :previous_event_hash, :text
      add :event_hash, :text, null: false
    end

    create unique_index(:security_audit_events, [:chain_scope, :sequence])
    create unique_index(:security_audit_events, [:chain_scope, :event_hash])

    create constraint(:security_audit_events, :security_audit_events_sequence_positive,
             check: "sequence > 0"
           )

    create constraint(:security_audit_events, :security_audit_events_previous_hash_shape,
             check: "previous_event_hash IS NULL OR previous_event_hash ~ '^[A-Za-z0-9_-]{43}$'"
           )

    create constraint(:security_audit_events, :security_audit_events_link_shape,
             check:
               "(sequence = 1 AND previous_event_hash IS NULL) OR (sequence > 1 AND previous_event_hash IS NOT NULL)"
           )

    create constraint(:security_audit_events, :security_audit_events_hash_shape,
             check: "event_hash ~ '^[A-Za-z0-9_-]{43}$'"
           )
  end

  def down do
    execute(
      "ALTER TABLE security_audit_events DROP CONSTRAINT IF EXISTS security_audit_events_hash_shape"
    )

    execute(
      "ALTER TABLE security_audit_events DROP CONSTRAINT IF EXISTS security_audit_events_link_shape"
    )

    execute(
      "ALTER TABLE security_audit_events DROP CONSTRAINT IF EXISTS security_audit_events_previous_hash_shape"
    )

    execute(
      "ALTER TABLE security_audit_events DROP CONSTRAINT IF EXISTS security_audit_events_sequence_positive"
    )

    drop index(:security_audit_events, [:chain_scope, :event_hash])
    drop index(:security_audit_events, [:chain_scope, :sequence])

    alter table(:security_audit_events) do
      remove :event_hash
      remove :previous_event_hash
      remove :sequence
      remove :chain_scope
    end
  end
end
