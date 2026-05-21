defmodule RefMDWeb.Schemas.CreateFolderShareKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateFolderShareKeyItem",
    type: :object,
    additionalProperties: false,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:share_id, :document_id, :encrypted_dek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.AddFolderShareKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AddFolderShareKeyItem",
    type: :object,
    additionalProperties: false,
    properties: %{
      share_id: %Schema{
        type: :string,
        format: :uuid,
        description: "New child share ID generated before encryption"
      },
      document_id: %Schema{type: :string, format: :uuid},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:share_id, :document_id, :encrypted_dek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.ReplaceFolderShareKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ReplaceFolderShareKeyItem",
    type: :object,
    additionalProperties: false,
    properties: %{
      share_id: %Schema{
        type: :string,
        format: :uuid,
        description: "Existing child share ID whose key will be replaced"
      },
      document_id: %Schema{type: :string, format: :uuid},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:share_id, :document_id, :encrypted_dek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.CreateDocumentShareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  }

  OpenApiSpex.schema(%{
    title: "CreateDocumentShareRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      scope: %Schema{type: :string, enum: ["document"]},
      share_slug: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      authorization_public_key_material: RefMDWeb.Schemas.ShareCapabilitySigningPublicKeyMaterial,
      share_capability_secret_commitment: @hash_schema,
      password_capability_secret_commitment: %Schema{
        oneOf: [@hash_schema, %Schema{type: :string, enum: ["none"]}]
      },
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      authenticated_workspace_pin_bootstrap_hash: @hash_schema,
      authenticated_workspace_pin_bootstrap: RefMDWeb.Schemas.WorkspacePinBootstrap,
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      salt: %Schema{type: :string},
      auth_key: %Schema{type: :string},
      kdf_params: %Schema{allOf: [RefMDWeb.Schemas.KdfParams]},
      expires_event_sequence: %Schema{type: :integer, minimum: 1},
      max_views: %Schema{type: :integer, minimum: 1},
      share_link_secret_backup_wraps: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.HybridKeyWrapFields
      },
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :id,
      :scope,
      :share_slug,
      :token_prefix,
      :authorization_public_key_material,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :permission,
      :password_protected,
      :authenticated_workspace_pin_bootstrap_hash,
      :authenticated_workspace_pin_bootstrap,
      :encrypted_dek,
      :nonce,
      :expires_event_sequence,
      :max_views,
      :share_link_secret_backup_wraps,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateFolderShareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  }

  OpenApiSpex.schema(%{
    title: "CreateFolderShareRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      scope: %Schema{type: :string, enum: ["folder"]},
      share_slug: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      authorization_public_key_material: RefMDWeb.Schemas.ShareCapabilitySigningPublicKeyMaterial,
      share_capability_secret_commitment: @hash_schema,
      password_capability_secret_commitment: %Schema{
        oneOf: [@hash_schema, %Schema{type: :string, enum: ["none"]}]
      },
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      authenticated_workspace_pin_bootstrap_hash: @hash_schema,
      authenticated_workspace_pin_bootstrap: RefMDWeb.Schemas.WorkspacePinBootstrap,
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      share_keys: %Schema{type: :array, items: RefMDWeb.Schemas.CreateFolderShareKeyItem},
      exclusions: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      },
      salt: %Schema{type: :string},
      auth_key: %Schema{type: :string},
      kdf_params: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          algorithm: %Schema{type: :string},
          memory: %Schema{type: :integer},
          iterations: %Schema{type: :integer},
          parallelism: %Schema{type: :integer},
          hash_length: %Schema{type: :integer}
        },
        required: [:algorithm, :memory, :iterations, :parallelism, :hash_length]
      },
      expires_event_sequence: %Schema{type: :integer, minimum: 1},
      max_views: %Schema{type: :integer, minimum: 1},
      share_link_secret_backup_wraps: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.HybridKeyWrapFields
      },
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :id,
      :scope,
      :share_slug,
      :token_prefix,
      :authorization_public_key_material,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :permission,
      :password_protected,
      :authenticated_workspace_pin_bootstrap_hash,
      :authenticated_workspace_pin_bootstrap,
      :encrypted_dek,
      :nonce,
      :share_keys,
      :expires_event_sequence,
      :max_views,
      :share_link_secret_backup_wraps,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateShareRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateShareRequest",
    oneOf: [
      RefMDWeb.Schemas.CreateDocumentShareRequest,
      RefMDWeb.Schemas.CreateFolderShareRequest
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareCreateResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareCreateResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_slug: %Schema{type: :string},
      event_sequence: %Schema{type: :integer, minimum: 1},
      event_hash: %Schema{type: :string}
    },
    required: [:id, :share_slug, :event_sequence, :event_hash]
  })
end
