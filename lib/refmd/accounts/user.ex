defmodule RefMD.Accounts.User do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "users" do
    field :email, :string
    field :name, :string
    field :encryption_setup_at, :utc_datetime_usec

    has_one :settings, RefMD.Accounts.UserSettings
    has_many :devices, RefMD.Accounts.Device
    has_many :sessions, RefMD.Accounts.Session

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :name, :encryption_setup_at])
    |> validate_required([:email, :name])
    |> unique_constraint(:email)
  end
end
