defmodule RefMD.Repo.Migrations.CreateSecurityCompoundAppendProtocol do
  use Ecto.Migration

  def change do
    create table(:security_pending_compound_intents, primary_key: false) do
      add :compound_intent_id, :binary_id, primary_key: true
      add :mutation_id, :binary_id, null: false
      add :challenge_id, :binary_id, null: false
      add :mutation_kind, :string, null: false

      add :actor_user_id, references(:users, type: :binary_id, on_delete: :delete_all),
        null: false

      add :actor_device_id, references(:devices, type: :binary_id, on_delete: :delete_all),
        null: false

      add :command_jcs_b64u, :text, null: false
      add :command_hash, :string, null: false
      add :intent_jcs_b64u, :text, null: false
      add :intent_hash, :string, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :consumed_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:security_pending_compound_intents, [:compound_intent_id, :mutation_id])
    create unique_index(:security_pending_compound_intents, [:challenge_id])

    create constraint(
             :security_pending_compound_intents,
             :security_pending_compound_intent_not_expired_at_create,
             check: "expires_at > created_at"
           )

    create table(:security_consumed_compound_intent_receipts, primary_key: false) do
      add :compound_intent_id, :binary_id, primary_key: true
      add :mutation_id, :binary_id, null: false
      add :protocol, :string, null: false
      add :version, :integer, null: false
      add :intent_hash, :string, null: false
      add :authorization_hash, :string, null: false
      add :response_status, :integer, null: false
      add :response_content_type, :string, null: false
      add :response_body_jcs_b64u, :text, null: false
      add :response_hash, :string, null: false
      add :committed_at, :utc_datetime_usec, null: false
    end

    create unique_index(:security_consumed_compound_intent_receipts, [
             :compound_intent_id,
             :mutation_id
           ])
  end
end
