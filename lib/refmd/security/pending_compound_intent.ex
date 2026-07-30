defmodule RefMD.Security.PendingCompoundIntent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:compound_intent_id, :binary_id, autogenerate: false}

  schema "security_pending_compound_intents" do
    field :mutation_id, :binary_id
    field :challenge_id, :binary_id
    field :mutation_kind, :string
    field :actor_user_id, :binary_id
    field :actor_device_id, :binary_id
    field :command_jcs_b64u, :string
    field :command_hash, :string
    field :intent_jcs_b64u, :string
    field :intent_hash, :string
    field :expires_at, :utc_datetime_usec
    field :consumed_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(intent, attrs) do
    intent
    |> cast(attrs, [
      :compound_intent_id,
      :mutation_id,
      :challenge_id,
      :mutation_kind,
      :actor_user_id,
      :actor_device_id,
      :command_jcs_b64u,
      :command_hash,
      :intent_jcs_b64u,
      :intent_hash,
      :expires_at,
      :consumed_at,
      :created_at
    ])
    |> validate_required([
      :compound_intent_id,
      :mutation_id,
      :challenge_id,
      :mutation_kind,
      :actor_user_id,
      :actor_device_id,
      :command_jcs_b64u,
      :command_hash,
      :intent_jcs_b64u,
      :intent_hash,
      :expires_at,
      :created_at
    ])
    |> unique_constraint([:compound_intent_id, :mutation_id])
  end
end
