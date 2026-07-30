defmodule RefMD.Security.MutationOutboxItem do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:outbox_id, :binary_id, autogenerate: true}
  @effect_kinds ~w(
    security_notification_delivery
    pubsub_broadcast
    push_delivery
    email_delivery
    pin_gossip_transport
    security_analytics
  )
  @statuses ~w(pending processing delivered)

  schema "security_mutation_outbox" do
    field :protocol, :string
    field :version, :integer
    field :compound_intent_id, Ecto.UUID
    field :mutation_id, Ecto.UUID
    field :effect_kind, :string
    field :effect_target_jcs_b64u, :string
    field :effect_target_hash, :string
    field :payload_jcs_b64u, :string
    field :payload_hash, :string
    field :idempotency_key, :string
    field :status, :string
    field :attempt_count, :integer
    field :available_at, :utc_datetime_usec
    field :lease_expires_at, :utc_datetime_usec
    field :delivered_at, :utc_datetime_usec
  end

  @fields [
    :protocol,
    :version,
    :compound_intent_id,
    :mutation_id,
    :effect_kind,
    :effect_target_jcs_b64u,
    :effect_target_hash,
    :payload_jcs_b64u,
    :payload_hash,
    :idempotency_key,
    :status,
    :attempt_count,
    :available_at,
    :lease_expires_at,
    :delivered_at
  ]

  def changeset(item, attrs) do
    item
    |> cast(attrs, @fields)
    |> validate_required(@fields -- [:lease_expires_at, :delivered_at])
    |> validate_inclusion(:effect_kind, @effect_kinds)
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:attempt_count, greater_than_or_equal_to: 0)
    |> unique_constraint(:idempotency_key)
    |> unique_constraint(
      [:compound_intent_id, :mutation_id, :effect_kind, :effect_target_hash],
      name: :security_mutation_outbox_effect_target_unique
    )
    |> check_constraint(:protocol, name: :security_mutation_outbox_protocol_check)
    |> check_constraint(:effect_kind, name: :security_mutation_outbox_effect_kind_check)
    |> check_constraint(:status, name: :security_mutation_outbox_status_check)
    |> check_constraint(:attempt_count, name: :security_mutation_outbox_attempt_count_check)
  end
end
