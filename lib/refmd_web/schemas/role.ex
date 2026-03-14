defmodule RefMDWeb.Schemas.PermissionOverride do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PermissionOverride",
    type: :object,
    properties: %{
      permission: %Schema{type: :string},
      granted: %Schema{type: :boolean}
    },
    required: [:permission, :granted]
  })
end

defmodule RefMDWeb.Schemas.RoleResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RoleResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      base_role: %Schema{type: :string, enum: ["owner", "admin", "editor", "viewer"]},
      is_default: %Schema{type: :boolean},
      catalog_version: %Schema{type: :integer, nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      permissions: %Schema{type: :array, items: RefMDWeb.Schemas.PermissionOverride}
    },
    required: [
      :id,
      :workspace_id,
      :name,
      :base_role,
      :is_default,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.RolesListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RolesListResponse",
    type: :object,
    properties: %{
      roles: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.RoleResponse}
    },
    required: [:roles]
  })
end

defmodule RefMDWeb.Schemas.CreateRoleRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateRoleRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string, minLength: 1, maxLength: 100},
      base_role: %Schema{type: :string, enum: ["admin", "editor", "viewer"]},
      permissions: %Schema{type: :array, items: RefMDWeb.Schemas.PermissionOverride}
    },
    required: [:name, :base_role]
  })
end

defmodule RefMDWeb.Schemas.UpdateRoleRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateRoleRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string, minLength: 1, maxLength: 100},
      is_default: %Schema{type: :boolean},
      permissions: %Schema{type: :array, items: RefMDWeb.Schemas.PermissionOverride}
    }
  })
end

defmodule RefMDWeb.Schemas.RoleDeleteResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RoleDeleteResponse",
    type: :object,
    properties: %{
      ok: %Schema{type: :boolean},
      invalidated_invitation_count: %Schema{type: :integer}
    },
    required: [:ok, :invalidated_invitation_count]
  })
end
