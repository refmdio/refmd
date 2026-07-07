defmodule RefMD.Encryption.UserEncryptedIdentityKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_encrypted_identity_keys" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :encrypted_identity_hybrid_encryption_private_key_material, :binary
    field :identity_hybrid_encryption_private_key_material_nonce, :binary
    field :encryption_key_id, :string
    field :encrypted_identity_hybrid_signing_private_key_material, :binary
    field :identity_hybrid_signing_private_key_material_nonce, :binary
    field :signing_key_id, :string

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @min_encrypted_material_bytes 16

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :user_id,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encryption_key_id,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :signing_key_id
    ])
    |> validate_required([
      :user_id,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encryption_key_id,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :signing_key_id
    ])
    |> validate_encrypted_material(:encrypted_identity_hybrid_encryption_private_key_material)
    |> validate_encrypted_material(:encrypted_identity_hybrid_signing_private_key_material)
    |> validate_nonce(:identity_hybrid_encryption_private_key_material_nonce)
    |> validate_nonce(:identity_hybrid_signing_private_key_material_nonce)
  end

  defp validate_encrypted_material(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) >= @min_encrypted_material_bytes do
        []
      else
        [{field, "must be a valid encrypted material blob"}]
      end
    end)
  end

  defp validate_nonce(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == 24 do
        []
      else
        [{field, "must be 24 bytes"}]
      end
    end)
  end
end
