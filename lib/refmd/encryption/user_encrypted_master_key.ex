defmodule RefMD.Encryption.UserEncryptedMasterKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_encrypted_master_keys" do
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    field :auth_type, :string
    field :encrypted_umk, :binary
    field :umk_nonce, :binary
    field :salt, :binary
    field :kdf_type, :string
    field :kdf_params, :map
    field :auth_key_hash, :string
    field :recovery_encrypted_umk, :binary
    field :recovery_nonce, :binary

    timestamps(type: :utc_datetime_usec)
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
      :recovery_nonce
    ])
    |> validate_required([:user_id, :auth_type, :recovery_encrypted_umk, :recovery_nonce])
    |> validate_inclusion(:auth_type, ~w(password oauth))
  end
end
