defmodule RefMD.Workspaces.WorkspaceRole do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspace_roles" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :name, :string
    field :base_role, :string
    field :is_default, :boolean, default: false
    field :catalog_version, :integer
    field :created_at, :utc_datetime_usec

    has_many :permissions, RefMD.Workspaces.WorkspaceRolePermission, foreign_key: :role_id
  end

  @type t :: %__MODULE__{}

  @base_roles ~w(owner admin editor viewer)

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(role, attrs) do
    role
    |> cast(attrs, [:workspace_id, :name, :base_role, :is_default, :catalog_version])
    |> validate_required([:workspace_id, :name, :base_role])
    |> validate_inclusion(:base_role, @base_roles)
  end
end
