defmodule RefMD.Repo.Migrations.CreateSecurityMutationOutbox do
  use Ecto.Migration

  def change do
    create table(:security_mutation_outbox, primary_key: false) do
      add :outbox_id, :binary_id, primary_key: true
      add :protocol, :string, null: false
      add :version, :integer, null: false
      add :compound_intent_id, :binary_id, null: false
      add :mutation_id, :binary_id, null: false
      add :effect_kind, :string, null: false
      add :effect_target_jcs_b64u, :text, null: false
      add :effect_target_hash, :string, null: false
      add :payload_jcs_b64u, :text, null: false
      add :payload_hash, :string, null: false
      add :idempotency_key, :string, null: false
      add :status, :string, null: false
      add :attempt_count, :integer, null: false
      add :available_at, :utc_datetime_usec, null: false
      add :lease_expires_at, :utc_datetime_usec
      add :delivered_at, :utc_datetime_usec
    end

    create unique_index(:security_mutation_outbox, [:idempotency_key])

    create unique_index(
             :security_mutation_outbox,
             [:compound_intent_id, :mutation_id, :effect_kind, :effect_target_hash],
             name: :security_mutation_outbox_effect_target_unique
           )

    create index(:security_mutation_outbox, [:status, :available_at])

    create constraint(:security_mutation_outbox, :security_mutation_outbox_protocol_check,
             check: "protocol = 'refmd.security-mutation-outbox' AND version = 1"
           )

    create constraint(:security_mutation_outbox, :security_mutation_outbox_effect_kind_check,
             check:
               "effect_kind IN ('security_notification_delivery', 'pubsub_broadcast', 'push_delivery', 'email_delivery', 'pin_gossip_transport', 'security_analytics')"
           )

    create constraint(:security_mutation_outbox, :security_mutation_outbox_status_check,
             check: "status IN ('pending', 'processing', 'delivered')"
           )

    create constraint(:security_mutation_outbox, :security_mutation_outbox_attempt_count_check,
             check: "attempt_count >= 0"
           )
  end
end
