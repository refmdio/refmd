defmodule RefMD.Encryption.UserIdentityPublicKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_identity_public_keys" do
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    field :ecdh_public_key, :binary
    field :signing_public_key, :binary

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(key, attrs) do
    key
    |> cast(attrs, [:user_id, :ecdh_public_key, :signing_public_key])
    |> validate_required([:user_id, :ecdh_public_key, :signing_public_key])
  end
end
