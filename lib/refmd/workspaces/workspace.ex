defmodule RefMD.Workspaces.Workspace do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspaces" do
    field :name, :string
    field :slug, :string
    field :description, :string
    field :icon, :string
    belongs_to :owner, RefMD.Accounts.User
    field :current_kek_version, :integer, default: 0
    field :min_kek_version, :integer, default: 0
    field :needs_kek_rotation, :boolean, default: false
    field :kek_rotation_initiator_user_id, :binary_id

    has_many :roles, RefMD.Workspaces.WorkspaceRole
    has_many :members, RefMD.Workspaces.WorkspaceMember

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(workspace, attrs) do
    workspace
    |> cast(attrs, [:name, :slug, :description, :icon, :owner_id])
    |> validate_required([:name, :slug, :owner_id])
    |> unique_constraint(:slug)
  end
end
