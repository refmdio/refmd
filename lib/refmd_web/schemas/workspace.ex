defmodule RefMDWeb.Schemas.WorkspaceResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      slug: %Schema{type: :string},
      description: %Schema{type: :string, nullable: true},
      icon: %Schema{type: :string, nullable: true},
      owner_id: %Schema{type: :string, format: :uuid},
      current_kek_version: %Schema{type: :integer},
      needs_kek_rotation: %Schema{type: :boolean},
      kek_rotation_initiator_user_id: %Schema{type: :string, format: :uuid, nullable: true},
      current_user_role_id: %Schema{type: :string, format: :uuid, nullable: true},
      current_user_base_role: %Schema{type: :string, nullable: true},
      is_default: %Schema{type: :boolean, nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :id,
      :name,
      :slug,
      :owner_id,
      :current_kek_version,
      :needs_kek_rotation,
      :created_at,
      :updated_at
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspacesListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspacesListResponse",
    type: :object,
    properties: %{
      workspaces: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.WorkspaceResponse}
    },
    required: [:workspaces]
  })
end

defmodule RefMDWeb.Schemas.CreateWorkspaceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateWorkspaceRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string, minLength: 1, maxLength: 100},
      description: %Schema{type: :string, maxLength: 500, nullable: true},
      icon: %Schema{type: :string, nullable: true}
    },
    required: [:name]
  })
end

defmodule RefMDWeb.Schemas.UpdateWorkspaceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateWorkspaceRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string, minLength: 1, maxLength: 100},
      slug: %Schema{type: :string, pattern: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"},
      description: %Schema{type: :string, maxLength: 500, nullable: true},
      icon: %Schema{type: :string, nullable: true}
    }
  })
end
