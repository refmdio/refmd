defmodule RefMD.Documents.DocumentSnapshot do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_snapshots" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :parent_snapshot, RefMD.Documents.DocumentSnapshot
    belongs_to :device, RefMD.Devices.Device

    field :latest_version, :integer
    field :data, :binary
    field :nonce, :binary
    field :key_version, :integer
    field :signature, :binary
    field :ciphertext_hash, :string
    field :clocks, :map
    field :parent_snapshot_update_clocks, :map
    field :parent_snapshot_proof, :string
    field :created_by_device, :string
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(snapshot, attrs) do
    snapshot
    |> cast(attrs, [
      :id,
      :document_id,
      :parent_snapshot_id,
      :device_id,
      :latest_version,
      :data,
      :nonce,
      :key_version,
      :signature,
      :ciphertext_hash,
      :clocks,
      :parent_snapshot_update_clocks,
      :parent_snapshot_proof,
      :created_by_device
    ])
    |> validate_required([
      :document_id,
      :device_id,
      :latest_version,
      :data,
      :nonce,
      :key_version,
      :signature,
      :ciphertext_hash,
      :clocks,
      :parent_snapshot_update_clocks,
      :parent_snapshot_proof,
      :created_by_device
    ])
  end
end
