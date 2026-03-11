defmodule RefMD.Auth.PopChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "pop_challenges" do
    belongs_to :user, RefMD.Users.User
    belongs_to :device, RefMD.Devices.Device
    field :challenge_hash, :binary
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [:user_id, :device_id, :challenge_hash, :expires_at])
    |> validate_required([:user_id, :device_id, :challenge_hash, :expires_at])
    |> unique_constraint(:challenge_hash)
  end
end
