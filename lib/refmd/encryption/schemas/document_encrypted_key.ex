defmodule RefMD.Encryption.DocumentEncryptedKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "document_encrypted_keys" do
    belongs_to :document, RefMD.Documents.Document, primary_key: true
    field :key_version, :integer, primary_key: true
    field :encrypted_dek, :binary
    field :nonce, :binary
    field :kek_version, :integer
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  alias RefMD.Crypto.Validate

  @dek_bytes 32

  def changeset(key, attrs) do
    key
    |> cast(attrs, [:document_id, :key_version, :encrypted_dek, :nonce, :kek_version, :is_active])
    |> validate_required([
      :document_id,
      :key_version,
      :encrypted_dek,
      :nonce,
      :kek_version,
      :is_active
    ])
    |> validate_number(:key_version, greater_than: 0)
    |> validate_number(:kek_version, greater_than: 0)
    |> Validate.validate_nonce()
    |> Validate.validate_wrapped_key(:encrypted_dek, @dek_bytes)
    |> unique_constraint([:document_id, :key_version],
      name: :document_encrypted_keys_pkey
    )
  end
end
