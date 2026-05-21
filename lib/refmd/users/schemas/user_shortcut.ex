defmodule RefMD.Users.UserShortcut do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_shortcuts" do
    belongs_to :user, RefMD.Users.User
    field :action, :string
    field :keys, :string

    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(shortcut, attrs) do
    shortcut
    |> cast(attrs, [:user_id, :action, :keys])
    |> validate_required([:user_id, :action, :keys])
    |> unique_constraint([:user_id, :action])
  end
end
