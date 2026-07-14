defmodule RefMD.Security.Notification do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Security.AuditEvent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @recipient_kinds ~w(user device workspace_role pending_registration)
  @severities ~w(info action_required warning critical)

  schema "security_notifications" do
    belongs_to :audit_event, AuditEvent

    field :recipient_kind, :string
    field :recipient_id, :string
    field :type, :string
    field :severity, :string
    field :action_ref, :map, default: %{}
    field :dedupe_key, :string
    field :expires_at, :utc_datetime_usec
    field :read_at, :utc_datetime_usec
    field :dismissed_at, :utc_datetime_usec
    field :acted_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @required_fields [:recipient_kind, :recipient_id, :type, :severity, :action_ref, :dedupe_key]

  def changeset(notification, attrs) do
    notification
    |> cast(
      attrs,
      @required_fields ++ [:audit_event_id, :expires_at, :read_at, :dismissed_at, :acted_at]
    )
    |> put_change(:action_ref, Map.get(attrs, :action_ref) || Map.get(attrs, "action_ref") || %{})
    |> validate_required(@required_fields)
    |> validate_inclusion(:recipient_kind, @recipient_kinds)
    |> validate_inclusion(:severity, @severities)
    |> validate_non_empty([:recipient_id, :type, :dedupe_key])
    |> foreign_key_constraint(:audit_event_id)
    |> unique_constraint([:recipient_kind, :recipient_id, :dedupe_key])
  end

  def payload(%__MODULE__{} = notification, audit_checkpoint) when is_map(audit_checkpoint) do
    %{
      id: notification.id,
      audit_event_id: notification.audit_event_id,
      audit_checkpoint: audit_checkpoint,
      recipient_kind: notification.recipient_kind,
      recipient_id: notification.recipient_id,
      type: notification.type,
      severity: notification.severity,
      action_ref: notification.action_ref || %{},
      dedupe_key: notification.dedupe_key,
      created_at: DateTime.to_iso8601(notification.created_at),
      expires_at: datetime_or_nil(notification.expires_at),
      read_at: datetime_or_nil(notification.read_at),
      dismissed_at: datetime_or_nil(notification.dismissed_at),
      acted_at: datetime_or_nil(notification.acted_at)
    }
  end

  defp validate_non_empty(changeset, fields) do
    Enum.reduce(fields, changeset, &validate_non_empty_field(&2, &1))
  end

  defp validate_non_empty_field(changeset, field) do
    validate_change(changeset, field, &non_empty_errors/2)
  end

  defp non_empty_errors(field, value) do
    if is_binary(value) and String.trim(value) != "" do
      []
    else
      [{field, "must not be empty"}]
    end
  end

  defp datetime_or_nil(nil), do: nil
  defp datetime_or_nil(datetime), do: DateTime.to_iso8601(datetime)
end
