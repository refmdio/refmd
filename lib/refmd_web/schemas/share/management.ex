defmodule RefMDWeb.Schemas.ShareListItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareListItem",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      scope: %Schema{type: :string, enum: ["document", "folder"]},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      token_prefix: %Schema{type: :string},
      max_views: %Schema{type: :integer, minimum: 1},
      view_count: %Schema{type: :integer},
      expires_event_sequence: %Schema{type: :integer},
      created_at: %Schema{type: :string, format: :"date-time"},
      salt: %Schema{type: :string, nullable: true},
      kdf_params: RefMDWeb.Schemas.KdfParams,
      child_shares: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.ShareChildListItem
      },
      exclusions: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}},
      share_link_secret_backup_wraps: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceOperationProvenSignedPqWrap
      }
    },
    required: [
      :id,
      :scope,
      :permission,
      :password_protected,
      :token_prefix,
      :view_count,
      :created_at,
      :child_shares,
      :exclusions,
      :share_link_secret_backup_wraps
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareChildListItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareChildListItem",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid}
    },
    required: [:share_id, :document_id]
  })
end

defmodule RefMDWeb.Schemas.ShareListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareListResponse",
    type: :object,
    properties: %{
      shares: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.ShareListItem
      }
    },
    required: [:shares]
  })
end

defmodule RefMDWeb.Schemas.ShareMetadata do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMetadata",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      scope: %Schema{type: :string, enum: ["document", "folder"]},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      created_event_hash: %Schema{type: :string},
      latest_bootstrap_event_hash: %Schema{type: :string},
      capability_context_hash: %Schema{type: :string},
      share_capability_secret_commitment: %Schema{type: :string},
      password_capability_secret_commitment: %Schema{type: :string}
    },
    required: [
      :id,
      :document_id,
      :scope,
      :permission,
      :password_protected,
      :created_event_hash,
      :latest_bootstrap_event_hash,
      :capability_context_hash,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment
    ]
  })
end

defmodule RefMDWeb.Schemas.UpdateShareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateShareRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      expires_event_sequence: %Schema{type: :integer, minimum: 1},
      max_views: %Schema{type: :integer, minimum: 1},
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    }
  })
end

defmodule RefMDWeb.Schemas.ShareManagementRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareManagementRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    }
  })
end

defmodule RefMDWeb.Schemas.ShareUpdateResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareUpdateResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      expires_event_sequence: %Schema{type: :integer},
      max_views: %Schema{type: :integer, minimum: 1},
      view_count: %Schema{type: :integer}
    },
    required: [:id, :expires_event_sequence, :max_views, :view_count]
  })
end

defmodule RefMDWeb.Schemas.UpdateShareExclusionsRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateShareExclusionsRequest",
    type: :object,
    anyOf: [
      %Schema{
        type: :object,
        additionalProperties: false,
        required: [:add],
        properties: %{
          add: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          },
          remove: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          },
          workspace_key_directory_events: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
        }
      },
      %Schema{
        type: :object,
        additionalProperties: false,
        required: [:remove],
        properties: %{
          add: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          },
          remove: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          },
          workspace_key_directory_events: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
        }
      }
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareExclusionsResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareExclusionsResponse",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      exclusions: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}}
    },
    required: [:share_id, :exclusions]
  })
end

defmodule RefMDWeb.Schemas.UpdateShareKeysRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateShareKeysRequest",
    type: :object,
    anyOf: [
      %Schema{
        type: :object,
        additionalProperties: false,
        required: [:add_keys],
        properties: %{
          add_keys: %Schema{type: :array, items: RefMDWeb.Schemas.AddFolderShareKeyItem},
          replace_keys: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.ReplaceFolderShareKeyItem
          },
          workspace_key_directory_events: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
        }
      },
      %Schema{
        type: :object,
        additionalProperties: false,
        required: [:replace_keys],
        properties: %{
          add_keys: %Schema{type: :array, items: RefMDWeb.Schemas.AddFolderShareKeyItem},
          replace_keys: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.ReplaceFolderShareKeyItem
          },
          workspace_key_directory_events: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
        }
      }
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareKeysUpdateResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareKeysUpdateResponse",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      added: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}},
      replaced: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}}
    },
    required: [:share_id, :added, :replaced]
  })
end
