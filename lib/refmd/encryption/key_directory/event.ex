defmodule RefMD.Encryption.KeyDirectory.Event do
  use Ecto.Schema
  import Ecto.Changeset
  alias RefMD.Encryption.KeyDirectory.Protocol

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "key_directory_events" do
    field :scope_kind, :string
    field :scope_id, :binary_id
    field :sequence, :integer
    field :event_type, :string
    field :event_hash, :string
    field :event_body_hash, :string
    field :previous_event_hash, :string
    field :payload, :map
    field :signatures, {:array, :map}

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @spec changeset(t(), map()) :: Ecto.Changeset.t()
  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :scope_kind,
      :scope_id,
      :sequence,
      :event_type,
      :event_hash,
      :event_body_hash,
      :previous_event_hash,
      :payload,
      :signatures
    ])
    |> validate_required([
      :scope_kind,
      :scope_id,
      :sequence,
      :event_type,
      :event_hash,
      :event_body_hash,
      :payload,
      :signatures
    ])
    |> validate_inclusion(:scope_kind, ["user", "workspace"])
    |> validate_number(:sequence, greater_than: 0)
    |> validate_change(:payload, &validate_payload/2)
    |> validate_change(:signatures, &validate_signatures/2)
    |> validate_integrity()
    |> unique_constraint([:scope_kind, :scope_id, :sequence])
    |> unique_constraint([:scope_kind, :scope_id, :event_hash])
  end

  defp validate_payload(:payload, payload) do
    Protocol.assert_event_payload!(payload)
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
      |> validate_literal(:event_type, payload["event_type"])
      |> validate_literal(:event_hash, Protocol.event_hash(payload))
      |> validate_literal(
        :event_body_hash,
        Protocol.event_body_hash(payload["body"])
      )
      |> validate_literal(:previous_event_hash, Map.get(payload, "previous_event_hash"))
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
