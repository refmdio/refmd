defmodule RefMD.Accounts.DeviceRevocationEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "device_revocation_events" do
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    field :device_id, :binary_id, primary_key: true
    field :revoked_by_device_id, :binary_id
    field :revocation_mode, :string
    field :signature, :binary
    field :revoked_at, :integer
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :user_id,
      :device_id,
      :revoked_by_device_id,
      :revocation_mode,
      :signature,
      :revoked_at
    ])
    |> validate_required([
      :user_id,
      :device_id,
      :revoked_by_device_id,
      :revocation_mode,
      :signature,
      :revoked_at
    ])
    |> validate_inclusion(:revocation_mode, ~w(security retire))
  end
end
