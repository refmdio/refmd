defmodule RefMD.Encryption.UserEncryptedIdentityKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_encrypted_identity_keys" do
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    field :encrypted_ecdh_private, :binary
    field :encrypted_ecdh_private_nonce, :binary
    field :encrypted_signing_private, :binary
    field :encrypted_signing_private_nonce, :binary

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :user_id,
      :encrypted_ecdh_private,
      :encrypted_ecdh_private_nonce,
      :encrypted_signing_private,
      :encrypted_signing_private_nonce
    ])
    |> validate_required([
      :user_id,
      :encrypted_ecdh_private,
      :encrypted_ecdh_private_nonce,
      :encrypted_signing_private,
      :encrypted_signing_private_nonce
    ])
  end
end
