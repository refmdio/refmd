defmodule RefMD.Auth.PendingGenesisIntent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:registration_id, :binary_id, autogenerate: false}

  schema "pending_genesis_intents" do
    field :compound_intent_id, :binary_id
    field :mutation_id, :binary_id
    field :prepare_request_jcs_b64u, :string
    field :prepare_request_hash, :string
    field :compound_intent_jcs_b64u, :string
    field :intent_hash, :string
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(intent, attrs) do
    intent
    |> cast(attrs, [
      :registration_id,
      :compound_intent_id,
      :mutation_id,
      :prepare_request_jcs_b64u,
      :prepare_request_hash,
      :compound_intent_jcs_b64u,
      :intent_hash,
      :expires_at,
      :created_at
    ])
    |> validate_required([
      :registration_id,
      :compound_intent_id,
      :mutation_id,
      :prepare_request_jcs_b64u,
      :prepare_request_hash,
      :compound_intent_jcs_b64u,
      :intent_hash,
      :expires_at,
      :created_at
    ])
    |> unique_constraint([:compound_intent_id, :mutation_id])
  end
end
