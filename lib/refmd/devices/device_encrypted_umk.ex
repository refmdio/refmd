defmodule RefMD.Devices.DeviceEncryptedUMK do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "device_encrypted_umks" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    belongs_to :device, RefMD.Devices.Device, primary_key: true
    field :sender_device_id, :binary_id
    field :encrypted_umk, :binary
    field :nonce, :binary
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  @xchacha20_nonce_bytes 24
  @encrypted_umk_bytes 48

  def changeset(key, attrs) do
    key
    |> cast(attrs, [:user_id, :device_id, :sender_device_id, :encrypted_umk, :nonce])
    |> validate_required([:user_id, :device_id, :sender_device_id, :encrypted_umk, :nonce])
    |> validate_binary_size(:nonce, @xchacha20_nonce_bytes)
    |> validate_binary_size(:encrypted_umk, @encrypted_umk_bytes)
    |> unique_constraint([:user_id, :device_id], name: :device_encrypted_umks_pkey)
  end

  defp validate_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
