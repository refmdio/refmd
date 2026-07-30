defmodule RefMD.Security.ConsumedCompoundIntentReceipt do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:compound_intent_id, :binary_id, autogenerate: false}

  schema "security_consumed_compound_intent_receipts" do
    field :mutation_id, :binary_id
    field :protocol, :string
    field :version, :integer
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
      :compound_intent_id,
      :mutation_id,
      :protocol,
      :version,
      :intent_hash,
      :authorization_hash,
      :response_status,
      :response_content_type,
      :response_body_jcs_b64u,
      :response_hash,
      :committed_at
    ])
    |> validate_required([
      :compound_intent_id,
      :mutation_id,
      :protocol,
      :version,
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
    |> validate_inclusion(:response_content_type, ["application/json"])
    |> validate_number(:response_status, greater_than_or_equal_to: 200, less_than: 300)
    |> unique_constraint([:compound_intent_id, :mutation_id])
  end
end
