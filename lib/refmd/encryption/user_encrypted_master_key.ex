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

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
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
    |> validate_auth_type_fields()
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
