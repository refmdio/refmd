defmodule RefMD.Encryption.UserEncryptedIdentityKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "user_encrypted_identity_keys" do
    belongs_to :user, RefMD.Users.User
    field :identity_key_epoch, :integer
    field :previous_record_hash, :string
    field :encrypted_identity_hybrid_encryption_private_key_material, :binary
    field :identity_hybrid_encryption_private_key_material_nonce, :binary
    field :encryption_key_id, :string
    field :encrypted_identity_hybrid_signing_private_key_material, :binary
    field :identity_hybrid_signing_private_key_material_nonce, :binary
    field :signing_key_id, :string
    field :signing_material_aad_hash, :string
    field :encryption_material_aad_hash, :string
    field :record_hash, :string
    field :is_current, :boolean

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @min_encrypted_material_bytes 16

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :user_id,
      :id,
      :identity_key_epoch,
      :previous_record_hash,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encryption_key_id,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :signing_key_id,
      :signing_material_aad_hash,
      :encryption_material_aad_hash,
      :record_hash,
      :is_current
    ])
    |> validate_required([
      :user_id,
      :id,
      :identity_key_epoch,
      :previous_record_hash,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encryption_key_id,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :signing_key_id,
      :signing_material_aad_hash,
      :encryption_material_aad_hash,
      :record_hash,
      :is_current
    ])
    |> validate_encrypted_material(:encrypted_identity_hybrid_encryption_private_key_material)
    |> validate_number(:identity_key_epoch, greater_than: 0)
    |> validate_encrypted_material(:encrypted_identity_hybrid_signing_private_key_material)
    |> validate_nonce(:identity_hybrid_encryption_private_key_material_nonce)
    |> validate_nonce(:identity_hybrid_signing_private_key_material_nonce)
    |> validate_format(:previous_record_hash, ~r/^(GENESIS|[A-Za-z0-9_-]{43})$/)
    |> validate_format(:signing_material_aad_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> validate_format(:encryption_material_aad_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> validate_format(:record_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> unique_constraint([:user_id, :identity_key_epoch])
    |> unique_constraint([:user_id, :record_hash])
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
