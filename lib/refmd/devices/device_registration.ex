defmodule RefMD.Devices.DeviceRegistration do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "device_registrations" do
    belongs_to :user, RefMD.Users.User
    field :name, :string
    field :device_type, :string
    field :ecdh_public_key, :binary
    field :signing_public_key, :binary
    field :client_nonce, :binary
    field :ip_address, :string
    field :created_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(device_registration, attrs) do
    device_registration
    |> cast(attrs, [
      :user_id,
      :name,
      :device_type,
      :ecdh_public_key,
      :signing_public_key,
      :client_nonce,
      :ip_address,
      :expires_at
    ])
    |> validate_required([
      :user_id,
      :name,
      :device_type,
      :ecdh_public_key,
      :signing_public_key,
      :client_nonce,
      :expires_at
    ])
    |> validate_inclusion(:device_type, ~w(browser desktop mobile))
    |> validate_byte_size(:ecdh_public_key, 32)
    |> validate_byte_size(:signing_public_key, 32)
    |> validate_byte_size(:client_nonce, 16)
  end

  defp validate_byte_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
