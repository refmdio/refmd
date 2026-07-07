defmodule RefMD.Encryption.UserIdentityPublicKey do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.{HybridEncryptionMaterial, Signature}

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_identity_public_keys" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :hybrid_encryption_public_key_material, :map
    field :encryption_key_id, :string
    field :hybrid_signing_public_key_material, :map
    field :signing_key_id, :string
    field :pending_registration_challenge_hash, :string
    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :user_id,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :pending_registration_challenge_hash
    ])
    |> validate_required([
      :user_id,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :pending_registration_challenge_hash
    ])
    |> validate_length(:pending_registration_challenge_hash, is: 43)
    |> validate_format(:pending_registration_challenge_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_hybrid_encryption_material()
    |> validate_hybrid_signing_material()
    |> unique_constraint(:signing_key_id,
      name: :user_identity_public_keys_signing_key_id_index
    )
  end

  defp validate_hybrid_encryption_material(changeset) do
    user_id = get_field(changeset, :user_id)

    changeset
    |> put_encryption_key_id()
    |> validate_change(:hybrid_encryption_public_key_material, fn field, material ->
      try do
        with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
             true <- material["owner_kind"] == "identity",
             true <- material["owner_id"] == user_id do
          []
        else
          _ -> [{field, "must be valid identity hybrid encryption public key material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid identity hybrid encryption public key material"}]
      end
    end)
  end

  defp put_encryption_key_id(changeset) do
    case get_change(changeset, :hybrid_encryption_public_key_material) do
      material when is_map(material) ->
        put_change(
          changeset,
          :encryption_key_id,
          HybridEncryptionMaterial.compute_key_id!(material)
        )

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end

  defp validate_hybrid_signing_material(changeset) do
    user_id = get_field(changeset, :user_id)

    validate_change(changeset, :hybrid_signing_public_key_material, fn field, material ->
      try do
        with :ok <- Signature.assert_public_key_material!(material),
             true <- material["owner_kind"] == "identity",
             true <- material["owner_id"] == user_id do
          []
        else
          _ -> [{field, "must be valid identity hybrid signing public key material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid identity hybrid signing public key material"}]
      end
    end)
    |> put_signing_key_id()
  end

  defp put_signing_key_id(changeset) do
    case get_change(changeset, :hybrid_signing_public_key_material) do
      material when is_map(material) ->
        put_change(changeset, :signing_key_id, Signature.compute_signing_key_id!(material))

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end
end
