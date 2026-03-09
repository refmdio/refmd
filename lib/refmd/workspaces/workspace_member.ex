defmodule RefMD.Workspaces.WorkspaceMember do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_members" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    field :role_id, :binary_id
    field :is_default, :boolean, default: false
    field :joined_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(member, attrs) do
    member
    |> cast(attrs, [:workspace_id, :user_id, :role_id, :is_default, :joined_at])
    |> validate_required([:workspace_id, :user_id, :role_id, :joined_at])
  end
end
