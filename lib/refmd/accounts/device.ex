defmodule RefMD.Accounts.Device do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "devices" do
    belongs_to :user, RefMD.Accounts.User
    field :name, :string
    field :device_type, :string
    field :ecdh_public_key, :binary
    field :signing_public_key, :binary
    field :identity_signature, :binary
    field :client_nonce, :binary
    field :last_seen_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(device, attrs) do
    device
    |> cast(attrs, [
      :user_id,
      :name,
      :device_type,
      :ecdh_public_key,
      :signing_public_key,
      :identity_signature,
      :client_nonce,
      :last_seen_at,
      :revoked_at
    ])
    |> validate_required([
      :user_id,
      :name,
      :device_type,
      :ecdh_public_key,
      :signing_public_key,
      :identity_signature,
      :client_nonce,
      :last_seen_at
    ])
    |> validate_inclusion(:device_type, ~w(browser desktop mobile))
    |> unique_constraint(:signing_public_key)
    |> unique_constraint(:ecdh_public_key)
  end
end
