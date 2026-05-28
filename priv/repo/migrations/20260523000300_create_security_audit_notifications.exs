defmodule RefMD.Repo.Migrations.CreateSecurityAuditNotifications do
  use Ecto.Migration

  def change do
    create table(:security_audit_events, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :class, :text, null: false
      add :type, :text, null: false
      add :actor, :map, null: false
      add :scope, :map, null: false
      add :resource, :map, null: false
      add :action, :map, null: false
      add :sensitivity, :map, null: false
      add :correlation, :map, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create index(:security_audit_events, [:class])
    create index(:security_audit_events, [:type])

    create index(:security_audit_events, ["(scope->>'workspace_id')"],
             name: :security_audit_events_workspace_id_index
           )

    create table(:security_notifications, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :audit_event_id,
          references(:security_audit_events, type: :binary_id, on_delete: :nilify_all)

      add :recipient_kind, :text, null: false
      add :recipient_id, :text, null: false
      add :type, :text, null: false
      add :severity, :text, null: false
      add :action_ref, :map, null: false, default: %{}
      add :dedupe_key, :text, null: false
      add :expires_at, :utc_datetime_usec
      add :read_at, :utc_datetime_usec
      add :dismissed_at, :utc_datetime_usec
      add :acted_at, :utc_datetime_usec

      timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
    end

    create index(:security_notifications, [:audit_event_id])
    create index(:security_notifications, [:recipient_kind, :recipient_id])
    create unique_index(:security_notifications, [:recipient_kind, :recipient_id, :dedupe_key])

    create constraint(:security_audit_events, :security_audit_events_class_check,
             check: "class IN ('authority', 'security_runtime')"
           )

    create constraint(:security_audit_events, :security_audit_events_action_result_check,
             check: "action->>'result' IN ('allowed', 'denied', 'failed', 'completed')"
           )

    create constraint(:security_notifications, :security_notifications_recipient_kind_check,
             check:
               "recipient_kind IN ('user', 'device', 'workspace_role', 'pending_registration')"
           )

    create constraint(:security_notifications, :security_notifications_severity_check,
             check: "severity IN ('info', 'action_required', 'warning', 'critical')"
           )
  end
end
