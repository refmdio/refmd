defmodule RefMD.Sharing.ShareKeyHistory do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "share_key_histories" do
    field :share_id, :binary_id, primary_key: true
    field :key_version, :integer, primary_key: true
    belongs_to :document, RefMD.Documents.Document
    field :encrypted_dek, :binary
    field :nonce, :binary

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [:share_id, :key_version, :document_id, :encrypted_dek, :nonce])
    |> validate_required([:share_id, :key_version, :document_id, :encrypted_dek, :nonce])
    |> validate_number(:key_version, greater_than: 0)
    |> validate_change(:nonce, fn :nonce, value ->
      if byte_size(value) == 24, do: [], else: [nonce: "must be 24 bytes"]
    end)
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:document_id)
  end
end
