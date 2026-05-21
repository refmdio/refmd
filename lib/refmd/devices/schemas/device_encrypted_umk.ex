defmodule RefMD.Devices.DeviceEncryptedUMK do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "device_encrypted_umks" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    belongs_to :device, RefMD.Devices.Device, primary_key: true
    field :sender_device_id, :binary_id
    field :initial_ake, :map
    field :initial_key_delivery, :map
    field :initial_kek_deliveries, :map
    field :device_state_delivery, :map
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :user_id,
      :device_id,
      :sender_device_id,
      :initial_ake,
      :initial_key_delivery,
      :initial_kek_deliveries,
      :device_state_delivery
    ])
    |> validate_required([
      :user_id,
      :device_id,
      :sender_device_id,
      :initial_ake,
      :initial_key_delivery,
      :initial_kek_deliveries,
      :device_state_delivery
    ])
    |> unique_constraint([:user_id, :device_id], name: :device_encrypted_umks_pkey)
  end
end
