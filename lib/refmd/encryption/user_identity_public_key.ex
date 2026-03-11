defmodule RefMD.Encryption.UserIdentityPublicKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_identity_public_keys" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :ecdh_public_key, :binary
    field :signing_public_key, :binary

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(key, attrs) do
    key
    |> cast(attrs, [:user_id, :ecdh_public_key, :signing_public_key])
    |> validate_required([:user_id, :ecdh_public_key, :signing_public_key])
    |> validate_byte_size(:ecdh_public_key, 32)
    |> validate_byte_size(:signing_public_key, 32)
  end

  defp validate_byte_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
