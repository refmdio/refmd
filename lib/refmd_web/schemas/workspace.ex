defmodule RefMDWeb.Schemas.PluginUserPolicy do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginUserPolicy",
    type: :object,
    nullable: true,
    properties: %{
      default_mode: %Schema{type: :string, enum: ["allow_safe", "allow_all", "deny_all"]},
      allowed_plugin_ids: %Schema{type: :array, items: %Schema{type: :string}},
      denied_plugin_ids: %Schema{type: :array, items: %Schema{type: :string}},
      require_admin_approval: %Schema{type: :boolean}
    }
  })
end

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
      encrypted_name: %Schema{type: :string, nullable: true},
      encrypted_name_nonce: %Schema{type: :string, nullable: true},
      encrypted_name_key_version: %Schema{type: :integer, nullable: true},
      encrypted_description: %Schema{type: :string, nullable: true},
      encrypted_description_nonce: %Schema{type: :string, nullable: true},
      encrypted_description_key_version: %Schema{type: :integer, nullable: true},
      encrypted_icon: %Schema{type: :string, nullable: true},
      encrypted_icon_nonce: %Schema{type: :string, nullable: true},
      encrypted_icon_key_version: %Schema{type: :integer, nullable: true},
      owner_id: %Schema{type: :string, format: :uuid},
      share_links_enabled: %Schema{type: :boolean},
      public_publishing_enabled: %Schema{type: :boolean},
      public_author_profile: RefMDWeb.Schemas.PublicAuthorProfile,
      guest_invites_enabled: %Schema{type: :boolean},
      guest_member_limit: %Schema{type: :integer, nullable: true},
      plugin_network_proxy: RefMDWeb.Schemas.PluginNetworkProxyRegistration,
      plugin_user_policy: RefMDWeb.Schemas.PluginUserPolicy,
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
      :share_links_enabled,
      :public_publishing_enabled,
      :guest_invites_enabled,
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
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_owner_role_id: %Schema{type: :string, format: :uuid},
      description: %Schema{type: :string, maxLength: 500, nullable: true},
      icon: %Schema{type: :string, nullable: true},
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :name,
      :workspace_id,
      :workspace_owner_role_id,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
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
      icon: %Schema{type: :string, nullable: true},
      encrypted_name: %Schema{type: :string, nullable: true},
      encrypted_name_nonce: %Schema{type: :string, nullable: true},
      encrypted_name_key_version: %Schema{type: :integer, nullable: true},
      encrypted_description: %Schema{type: :string, nullable: true},
      encrypted_description_nonce: %Schema{type: :string, nullable: true},
      encrypted_description_key_version: %Schema{type: :integer, nullable: true},
      encrypted_icon: %Schema{type: :string, nullable: true},
      encrypted_icon_nonce: %Schema{type: :string, nullable: true},
      encrypted_icon_key_version: %Schema{type: :integer, nullable: true},
      guest_invites_enabled: %Schema{type: :boolean},
      guest_member_limit: %Schema{type: :integer, nullable: true}
    }
  })
end

defmodule RefMDWeb.Schemas.UpdateWorkspaceFeaturesRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateWorkspaceFeaturesRequest",
    type: :object,
    properties: %{
      share_links_enabled: %Schema{type: :boolean},
      public_publishing_enabled: %Schema{type: :boolean},
      guest_invites_enabled: %Schema{type: :boolean},
      guest_member_limit: %Schema{type: :integer, nullable: true},
      plugin_network_proxy: RefMDWeb.Schemas.PluginNetworkProxyRegistration,
      plugin_user_policy: RefMDWeb.Schemas.PluginUserPolicy,
      public_author_display_name: %Schema{type: :string, nullable: true},
      public_author_slug: %Schema{type: :string, nullable: true},
      public_author_bio: %Schema{type: :string, nullable: true}
    }
  })
end
