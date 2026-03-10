defmodule RefMD.Encryption.DeviceEncryptedUMK do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "device_encrypted_umks" do
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    belongs_to :device, RefMD.Accounts.Device, primary_key: true
    field :sender_device_id, :binary_id
    field :encrypted_umk, :binary
    field :nonce, :binary
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(key, attrs) do
    key
    |> cast(attrs, [:user_id, :device_id, :sender_device_id, :encrypted_umk, :nonce])
    |> validate_required([:user_id, :device_id, :sender_device_id, :encrypted_umk, :nonce])
    |> unique_constraint([:user_id, :device_id], name: :device_encrypted_umks_pkey)
  end
end
