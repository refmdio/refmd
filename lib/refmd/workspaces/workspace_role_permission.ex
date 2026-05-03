defmodule RefMD.Workspaces.WorkspaceRolePermission do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_role_permissions" do
    belongs_to :role, RefMD.Workspaces.WorkspaceRole, primary_key: true
    field :permission, :string, primary_key: true
    field :granted, :boolean
  end

  @type t :: %__MODULE__{}

  @permissions ~w(
    document:read document:write document:delete document:archive
    workspace:update workspace:features workspace:admin workspace:delete
    member:list member:invite guest:invite member:change_role member:remove
    role:manage
  )

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(perm, attrs) do
    perm
    |> cast(attrs, [:role_id, :permission, :granted])
    |> validate_required([:role_id, :permission, :granted])
    |> validate_inclusion(:permission, @permissions)
  end
end
