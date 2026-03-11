defmodule RefMD.Auth.Session do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "sessions" do
    belongs_to :user, RefMD.Users.User
    belongs_to :device, RefMD.Devices.Device
    field :token_hash, :string
    field :remember_me, :boolean
    field :is_recovery, :boolean, default: false
    belongs_to :device_registration, RefMD.Devices.DeviceRegistration
    field :ip_address, :string
    field :user_agent, :string
    field :expires_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec
    field :last_verified_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(session, attrs) do
    session
    |> cast(attrs, [
      :user_id,
      :device_id,
      :token_hash,
      :remember_me,
      :is_recovery,
      :device_registration_id,
      :ip_address,
      :user_agent,
      :expires_at,
      :last_seen_at
    ])
    |> validate_required([:user_id, :token_hash, :remember_me, :expires_at, :last_seen_at])
    |> unique_constraint(:token_hash)
  end
end
