defmodule RefMD.Encryption.KeyDirectory.Checkpoint do
  use Ecto.Schema
  import Ecto.Changeset
  alias RefMD.Crypto.Suite
  alias RefMD.Encryption.KeyDirectory.Protocol

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "key_directory_checkpoints" do
    field :scope_kind, :string
    field :scope_id, :binary_id
    field :sequence, :integer
    field :checkpoint_hash, :string
    field :previous_checkpoint_hash, :string
    field :covered_event_head_sequence, :integer
    field :covered_event_head_hash, :string
    field :suite_policy_version, :integer
    field :min_suite_rank, :integer
    field :allowed_suite_ids_hash, :string
    field :payload, :map
    field :signatures, {:array, :map}

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(checkpoint, attrs) do
    checkpoint
    |> cast(attrs, [
      :scope_kind,
      :scope_id,
      :sequence,
      :checkpoint_hash,
      :previous_checkpoint_hash,
      :covered_event_head_sequence,
      :covered_event_head_hash,
      :suite_policy_version,
      :min_suite_rank,
      :allowed_suite_ids_hash,
      :payload,
      :signatures
    ])
    |> validate_required([
      :scope_kind,
      :scope_id,
      :sequence,
      :checkpoint_hash,
      :covered_event_head_sequence,
      :covered_event_head_hash,
      :suite_policy_version,
      :min_suite_rank,
      :allowed_suite_ids_hash,
      :payload,
      :signatures
    ])
    |> validate_inclusion(:scope_kind, ["user", "workspace"])
    |> validate_number(:sequence, greater_than: 0)
    |> validate_change(:payload, &validate_payload/2)
    |> validate_change(:signatures, &validate_signatures/2)
    |> validate_integrity()
    |> unique_constraint([:scope_kind, :scope_id, :sequence])
    |> unique_constraint([:scope_kind, :scope_id, :checkpoint_hash])
  end

  defp validate_payload(:payload, payload) do
    Protocol.assert_checkpoint_payload!(payload)
    []
  rescue
    ArgumentError -> [payload: "is invalid"]
  end

  defp validate_signatures(:signatures, signatures) when is_list(signatures) and signatures != [],
    do: []

  defp validate_signatures(:signatures, _), do: [signatures: "must be a list"]

  defp validate_integrity(changeset) do
    payload = get_field(changeset, :payload)

    if is_map(payload) do
      changeset
      |> validate_literal(:scope_kind, payload["scope_kind"])
      |> validate_literal(:scope_id, payload["scope_id"])
      |> validate_literal(:sequence, payload["sequence"])
      |> validate_literal(
        :checkpoint_hash,
        Protocol.checkpoint_hash(payload)
      )
      |> validate_literal(:previous_checkpoint_hash, Map.get(payload, "previous_checkpoint_hash"))
      |> validate_literal(
        :covered_event_head_sequence,
        payload["covered_event_head"]["head_sequence"]
      )
      |> validate_literal(:covered_event_head_hash, payload["covered_event_head"]["head_hash"])
      |> validate_literal(:suite_policy_version, payload["suite_policy_version"])
      |> validate_literal(:min_suite_rank, payload["min_suite_rank"])
      |> validate_literal(
        :allowed_suite_ids_hash,
        Suite.canonical_allowed_suite_ids_hash(payload)
      )
    else
      changeset
    end
  rescue
    ArgumentError -> add_error(changeset, :payload, "is invalid")
  end

  defp validate_literal(changeset, field, expected) do
    if get_field(changeset, field) == expected do
      changeset
    else
      add_error(changeset, field, "does not match payload")
    end
  end
end
