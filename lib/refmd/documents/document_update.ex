defmodule RefMD.Documents.DocumentUpdate do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_updates" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :snapshot, RefMD.Documents.DocumentSnapshot

    field :device_id, Ecto.UUID
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

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(update, attrs) do
    update
    |> cast(attrs, [
      :document_id,
      :snapshot_id,
      :device_id,
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
    |> validate_update_auth_fields()
    |> unique_constraint([:document_id, :version],
      name: :document_updates_document_id_version_index
    )
    |> unique_constraint([:document_id, :update_hash],
      name: :document_updates_document_id_update_hash_index
    )
  end

  defp validate_update_auth_fields(changeset) do
    changeset
    |> validate_required([:signature, :clock, :device_signing_pub_key, :device_id])
    |> reject_field(:mac, "must not be set")
    |> reject_field(:share_id, "must not be set")
  end

  defp reject_field(changeset, field, msg) do
    if get_field(changeset, field) do
      add_error(changeset, field, msg)
    else
      changeset
    end
  end
end
