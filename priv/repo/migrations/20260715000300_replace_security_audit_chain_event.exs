defmodule RefMD.Repo.Migrations.ReplaceSecurityAuditChainEvent do
  use Ecto.Migration

  def up do
    execute("DELETE FROM security_audit_events")

    execute(
      "ALTER TABLE security_audit_events DROP CONSTRAINT IF EXISTS security_audit_events_link_shape"
    )

    execute(
      "ALTER TABLE security_audit_events DROP CONSTRAINT IF EXISTS security_audit_events_previous_hash_shape"
    )

    alter table(:security_audit_events) do
      add :chain_scope_kind, :text, null: false
      add :chain_scope_id, :binary_id, null: false
      add :event_body, :map, null: false
      modify :previous_event_hash, :text, null: false
    end

    create constraint(:security_audit_events, :security_audit_events_scope_kind,
             check: "chain_scope_kind IN ('user', 'workspace')"
           )

    create constraint(:security_audit_events, :security_audit_events_previous_hash_shape,
             check:
               "previous_event_hash = 'GENESIS' OR previous_event_hash ~ '^[A-Za-z0-9_-]{43}$'"
           )

    create constraint(:security_audit_events, :security_audit_events_link_shape,
             check:
               "(sequence = 1 AND previous_event_hash = 'GENESIS') OR (sequence > 1 AND previous_event_hash <> 'GENESIS')"
           )
  end

  def down do
    raise "latest design replacement is intentionally irreversible"
  end
end
