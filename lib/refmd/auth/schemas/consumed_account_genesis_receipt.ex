defmodule RefMD.Auth.ConsumedAccountGenesisReceipt do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:registration_id, :binary_id, autogenerate: false}

  schema "consumed_account_genesis_receipts" do
    field :protocol, :string
    field :version, :integer
    field :compound_intent_id, :binary_id
    field :mutation_id, :binary_id
    field :intent_hash, :string
    field :authorization_hash, :string
    field :response_status, :integer
    field :response_content_type, :string
    field :response_body_jcs_b64u, :string
    field :response_hash, :string
    field :committed_at, :utc_datetime_usec
  end

  def changeset(receipt, attrs) do
    receipt
    |> cast(attrs, [
      :registration_id,
      :protocol,
      :version,
      :compound_intent_id,
      :mutation_id,
      :intent_hash,
      :authorization_hash,
      :response_status,
      :response_content_type,
      :response_body_jcs_b64u,
      :response_hash,
      :committed_at
    ])
    |> validate_required([
      :registration_id,
      :protocol,
      :version,
      :compound_intent_id,
      :mutation_id,
      :intent_hash,
      :authorization_hash,
      :response_status,
      :response_content_type,
      :response_body_jcs_b64u,
      :response_hash,
      :committed_at
    ])
    |> validate_inclusion(:protocol, ["refmd.audit.consumed-compound-intent-receipt"])
    |> validate_inclusion(:version, [1])
    |> validate_inclusion(:response_status, [201])
    |> validate_inclusion(:response_content_type, ["application/json"])
    |> unique_constraint([:compound_intent_id, :mutation_id])
  end
end
