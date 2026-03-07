defmodule RefMD.Encryption.DocumentEncryptedKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "document_encrypted_keys" do
    belongs_to :document, RefMD.Documents.Document
    field :key_version, :integer, primary_key: true
    field :encrypted_dek, :binary
    field :nonce, :binary
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [:document_id, :key_version, :encrypted_dek, :nonce, :is_active])
    |> validate_required([:document_id, :key_version, :encrypted_dek, :nonce, :is_active])
  end
end
