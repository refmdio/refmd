defmodule RefMD.Encryption.UserEncryptedMasterKey do
  use Ecto.Schema
  import Ecto.Changeset
  alias RefMD.Crypto.{JCS, Signature}

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_encrypted_master_keys" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :auth_type, :string
    field :encrypted_umk, :binary
    field :umk_nonce, :binary
    field :salt, :binary
    field :kdf_type, :string
    field :kdf_params, :map
    field :auth_key_hash, :string
    field :recovery_encrypted_umk, :binary
    field :recovery_nonce, :binary
    field :recovery_authorization_public_material, :map
    field :recovery_authorization_key_id, :string

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :user_id,
      :auth_type,
      :encrypted_umk,
      :umk_nonce,
      :salt,
      :kdf_type,
      :kdf_params,
      :auth_key_hash,
      :recovery_encrypted_umk,
      :recovery_nonce,
      :recovery_authorization_public_material,
      :recovery_authorization_key_id
    ])
    |> validate_required([
      :user_id,
      :auth_type,
      :recovery_encrypted_umk,
      :recovery_nonce,
      :recovery_authorization_public_material,
      :recovery_authorization_key_id
    ])
    |> validate_inclusion(:auth_type, ~w(password oauth))
    |> validate_recovery_authorization_material()
    |> validate_auth_type_fields()
  end

  defp validate_recovery_authorization_material(changeset) do
    user_id = get_field(changeset, :user_id)
    key_id = get_field(changeset, :recovery_authorization_key_id)

    validate_change(changeset, :recovery_authorization_public_material, fn
      :recovery_authorization_public_material, material ->
        with true <- is_map(material),
             canonical when is_binary(canonical) <- JCS.canonical_bytes!(material),
             :ok <- Signature.assert_public_key_material!(material),
             true <- material["owner_kind"] == "identity",
             true <- is_nil(user_id) or material["owner_id"] == user_id,
             true <- is_nil(key_id) or Signature.compute_signing_key_id!(material) == key_id do
          []
        else
          _ ->
            [
              recovery_authorization_public_material:
                "must be canonical hybrid signing public key material"
            ]
        end
    end)
  end

  defp validate_auth_type_fields(changeset) do
    case get_field(changeset, :auth_type) do
      "password" ->
        changeset
        |> validate_required([
          :encrypted_umk,
          :umk_nonce,
          :salt,
          :kdf_type,
          :kdf_params,
          :auth_key_hash
        ])
        |> validate_inclusion(:kdf_type, ~w(argon2id))

      "oauth" ->
        changeset
        |> reject_password_fields()

      _ ->
        changeset
    end
  end

  defp reject_password_fields(changeset) do
    Enum.reduce(
      [:encrypted_umk, :umk_nonce, :salt, :kdf_type, :kdf_params, :auth_key_hash],
      changeset,
      fn field, cs ->
        if get_field(cs, field) do
          add_error(cs, field, "must not be set for oauth auth_type")
        else
          cs
        end
      end
    )
  end
end
