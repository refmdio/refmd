defmodule RefMD.Documents.DocumentUpdate do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_updates" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :snapshot, RefMD.Documents.DocumentSnapshot

    field :clock, :integer
    field :version, :integer
    field :device_signing_pub_key, :string
    field :update_data, :binary
    field :nonce, :binary
    field :key_version, :integer
    field :update_hash, :string
    field :signature, :binary
    field :mac, :binary
    field :share_id, :binary_id
    field :timestamp, :integer
    field :created_at, :utc_datetime_usec
  end

  def changeset(update, attrs) do
    update
    |> cast(attrs, [
      :document_id,
      :snapshot_id,
      :clock,
      :version,
      :device_signing_pub_key,
      :update_data,
      :nonce,
      :key_version,
      :update_hash,
      :signature,
      :mac,
      :share_id,
      :timestamp
    ])
    |> validate_required([
      :document_id,
      :snapshot_id,
      :version,
      :update_data,
      :nonce,
      :key_version,
      :update_hash,
      :timestamp
    ])
    |> unique_constraint(:update_hash)
  end
end
