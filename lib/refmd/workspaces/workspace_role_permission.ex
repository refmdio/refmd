defmodule RefMD.Workspaces.WorkspaceRolePermission do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_role_permissions" do
    belongs_to :role, RefMD.Workspaces.WorkspaceRole
    field :permission, :string, primary_key: true
    field :granted, :boolean
  end

  @permissions ~w(
    document:read document:write document:delete document:archive
    workspace:update workspace:admin workspace:delete
    member:list member:invite member:change_role member:remove
    role:manage
  )

  def changeset(perm, attrs) do
    perm
    |> cast(attrs, [:role_id, :permission, :granted])
    |> validate_required([:role_id, :permission, :granted])
    |> validate_inclusion(:permission, @permissions)
  end
end
