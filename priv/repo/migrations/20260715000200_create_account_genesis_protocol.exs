defmodule RefMD.Repo.Migrations.CreateAccountGenesisProtocol do
  use Ecto.Migration

  def change do
    create table(:pending_account_geneses, primary_key: false) do
      add :registration_id, :binary_id, primary_key: true
      add :reserved_user_id, :binary_id, null: false
      add :reserved_workspace_id, :binary_id, null: false
      add :reserved_workspace_role_ids, :map, null: false
      add :normalized_email, :string, null: false
      add :display_name, :string, null: false
      add :credential, :map, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :consumed_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:pending_account_geneses, [:reserved_user_id])
    create unique_index(:pending_account_geneses, [:reserved_workspace_id])
    create unique_index(:pending_account_geneses, [:normalized_email])

    create table(:pending_genesis_sessions, primary_key: false) do
      add :registration_id,
          references(:pending_account_geneses,
            column: :registration_id,
            type: :binary_id,
            on_delete: :delete_all
          ),
          primary_key: true

      add :token_hash, :string, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :consumed_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:pending_genesis_sessions, [:token_hash])

    create table(:pending_genesis_challenges, primary_key: false) do
      add :registration_id,
          references(:pending_account_geneses,
            column: :registration_id,
            type: :binary_id,
            on_delete: :delete_all
          ),
          primary_key: true

      add :pending_genesis_session_token_hash, :string, null: false
      add :challenge_hash, :string, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :consumed_at, :utc_datetime_usec
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:pending_genesis_challenges, [:challenge_hash])

    create table(:pending_genesis_intents, primary_key: false) do
      add :registration_id,
          references(:pending_account_geneses,
            column: :registration_id,
            type: :binary_id,
            on_delete: :delete_all
          ),
          primary_key: true

      add :compound_intent_id, :binary_id, null: false
      add :mutation_id, :binary_id, null: false
      add :prepare_request_jcs_b64u, :text, null: false
      add :prepare_request_hash, :string, null: false
      add :compound_intent_jcs_b64u, :text, null: false
      add :intent_hash, :string, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:pending_genesis_intents, [:compound_intent_id, :mutation_id])

    create table(:consumed_account_genesis_receipts, primary_key: false) do
      add :registration_id, :binary_id, primary_key: true
      add :protocol, :string, null: false
      add :version, :integer, null: false
      add :compound_intent_id, :binary_id, null: false
      add :mutation_id, :binary_id, null: false
      add :intent_hash, :string, null: false
      add :authorization_hash, :string, null: false
      add :response_status, :integer, null: false
      add :response_content_type, :string, null: false
      add :response_body_jcs_b64u, :text, null: false
      add :response_hash, :string, null: false
      add :committed_at, :utc_datetime_usec, null: false
    end

    create unique_index(:consumed_account_genesis_receipts, [
             :compound_intent_id,
             :mutation_id
           ])

    create constraint(:pending_account_geneses, :pending_account_genesis_not_expired_at_create,
             check: "expires_at > created_at"
           )

    create constraint(:pending_genesis_sessions, :pending_genesis_session_not_expired_at_create,
             check: "expires_at > created_at"
           )

    create constraint(
             :pending_genesis_challenges,
             :pending_genesis_challenge_not_expired_at_create,
             check: "expires_at > created_at"
           )

    create constraint(:pending_genesis_intents, :pending_genesis_intent_not_expired_at_create,
             check: "expires_at > created_at"
           )
  end
end
