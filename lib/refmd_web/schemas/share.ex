defmodule RefMDWeb.Schemas.CreateFolderShareKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateFolderShareKeyItem",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true}
    },
    required: [:share_id, :document_id, :encrypted_dek]
  })
end

defmodule RefMDWeb.Schemas.AddFolderShareKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AddFolderShareKeyItem",
    type: :object,
    properties: %{
      share_id: %Schema{
        type: :string,
        format: :uuid,
        description: "New child share ID generated before encryption"
      },
      document_id: %Schema{type: :string, format: :uuid},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true}
    },
    required: [:share_id, :document_id, :encrypted_dek]
  })
end

defmodule RefMDWeb.Schemas.ReplaceFolderShareKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ReplaceFolderShareKeyItem",
    type: :object,
    properties: %{
      share_id: %Schema{
        type: :string,
        format: :uuid,
        description: "Existing child share ID whose key will be replaced"
      },
      document_id: %Schema{type: :string, format: :uuid},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true}
    },
    required: [:share_id, :document_id, :encrypted_dek]
  })
end

defmodule RefMDWeb.Schemas.CreateDocumentShareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDocumentShareRequest",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      scope: %Schema{type: :string, enum: ["document"]},
      share_slug: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      salt: %Schema{type: :string, nullable: true},
      kdf_params: %Schema{allOf: [RefMDWeb.Schemas.KdfParams], nullable: true},
      auth_key: %Schema{type: :string, nullable: true},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      access_limit: %Schema{type: :integer, nullable: true}
    },
    required: [
      :id,
      :scope,
      :share_slug,
      :token_prefix,
      :permission,
      :password_protected,
      :encrypted_dek
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateFolderShareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateFolderShareRequest",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      scope: %Schema{type: :string, enum: ["folder"]},
      share_slug: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      share_keys: %Schema{type: :array, items: RefMDWeb.Schemas.CreateFolderShareKeyItem},
      exclusions: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid},
        nullable: true
      },
      salt: %Schema{type: :string, nullable: true},
      kdf_params: %Schema{
        type: :object,
        nullable: true,
        properties: %{
          algorithm: %Schema{type: :string},
          memory: %Schema{type: :integer},
          iterations: %Schema{type: :integer},
          parallelism: %Schema{type: :integer},
          hash_length: %Schema{type: :integer}
        },
        required: [:algorithm, :memory, :iterations, :parallelism, :hash_length]
      },
      auth_key: %Schema{type: :string, nullable: true},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      access_limit: %Schema{type: :integer, nullable: true}
    },
    required: [
      :id,
      :scope,
      :share_slug,
      :token_prefix,
      :permission,
      :password_protected,
      :encrypted_dek,
      :share_keys
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
      share_manage_token: %Schema{type: :string}
    },
    required: [:id, :share_slug, :share_manage_token]
  })
end

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
      share_slug: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      access_limit: %Schema{type: :integer, nullable: true},
      access_count: %Schema{type: :integer},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      salt: %Schema{type: :string, nullable: true},
      kdf_params: RefMDWeb.Schemas.KdfParams,
      child_shares: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.ShareChildListItem
      },
      exclusions: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}}
    },
    required: [
      :id,
      :scope,
      :permission,
      :password_protected,
      :share_slug,
      :token_prefix,
      :access_count,
      :created_at,
      :child_shares,
      :exclusions
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
      password_protected: %Schema{type: :boolean}
    },
    required: [:id, :document_id, :scope, :permission, :password_protected]
  })
end

defmodule RefMDWeb.Schemas.UpdateShareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateShareRequest",
    type: :object,
    properties: %{
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      access_limit: %Schema{type: :integer, nullable: true}
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
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      access_limit: %Schema{type: :integer, nullable: true},
      access_count: %Schema{type: :integer}
    },
    required: [:id, :access_count]
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
        required: [:add],
        properties: %{
          add: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          },
          remove: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          }
        }
      },
      %Schema{
        type: :object,
        required: [:remove],
        properties: %{
          add: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          },
          remove: %Schema{
            type: :array,
            items: %Schema{type: :string, format: :uuid}
          }
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
        required: [:add_keys],
        properties: %{
          add_keys: %Schema{type: :array, items: RefMDWeb.Schemas.AddFolderShareKeyItem},
          replace_keys: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.ReplaceFolderShareKeyItem
          }
        }
      },
      %Schema{
        type: :object,
        required: [:replace_keys],
        properties: %{
          add_keys: %Schema{type: :array, items: RefMDWeb.Schemas.AddFolderShareKeyItem},
          replace_keys: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.ReplaceFolderShareKeyItem
          }
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

defmodule RefMDWeb.Schemas.DocumentShareRoot do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentShareRoot",
    type: :object,
    properties: %{
      kind: %Schema{type: :string, enum: ["document"]},
      document_token: %Schema{type: :string}
    },
    required: [:kind, :document_token]
  })
end

defmodule RefMDWeb.Schemas.FolderShareRoot do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "FolderShareRoot",
    type: :object,
    properties: %{
      kind: %Schema{type: :string, enum: ["folder"]},
      folder_token: %Schema{type: :string}
    },
    required: [:kind, :folder_token]
  })
end

defmodule RefMDWeb.Schemas.ShareLandingResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareLandingResponse",
    type: :object,
    properties: %{
      share: RefMDWeb.Schemas.ShareMetadata,
      root: %Schema{
        oneOf: [
          RefMDWeb.Schemas.DocumentShareRoot,
          RefMDWeb.Schemas.FolderShareRoot
        ]
      }
    },
    required: [:share, :root]
  })
end

defmodule RefMDWeb.Schemas.ShareBootstrapRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareBootstrapRequest",
    type: :object,
    properties: %{
      display_name: %Schema{type: :string},
      device_signing_pub_key: %Schema{type: :string},
      device_encryption_pub_key: %Schema{type: :string}
    },
    required: [:display_name, :device_signing_pub_key, :device_encryption_pub_key]
  })
end

defmodule RefMDWeb.Schemas.SharePasswordChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SharePasswordChallengeResponse",
    type: :object,
    properties: %{
      challenge: %Schema{type: :string},
      salt: %Schema{type: :string},
      kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:challenge, :salt, :kdf_params]
  })
end

defmodule RefMDWeb.Schemas.SharePasswordChallengeRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SharePasswordChallengeRequest",
    type: :object,
    properties: %{
      response: %Schema{type: :string},
      display_name: %Schema{type: :string},
      device_signing_pub_key: %Schema{type: :string},
      device_encryption_pub_key: %Schema{type: :string}
    },
    required: [:response, :display_name, :device_signing_pub_key, :device_encryption_pub_key]
  })
end

defmodule RefMDWeb.Schemas.ShareParticipantInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareParticipantInfo",
    type: :object,
    properties: %{
      principal_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      grant: %Schema{type: :string, enum: ["view", "edit"]}
    },
    required: [:principal_id, :device_id, :grant]
  })
end

defmodule RefMDWeb.Schemas.ShareBootstrapResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareBootstrapResponse",
    type: :object,
    properties: %{
      root: %Schema{
        oneOf: [
          RefMDWeb.Schemas.DocumentShareRoot,
          RefMDWeb.Schemas.FolderShareRoot
        ]
      },
      participant: RefMDWeb.Schemas.ShareParticipantInfo
    },
    required: [:root, :participant]
  })
end

defmodule RefMDWeb.Schemas.ShareVerificationDirectory do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareVerificationDirectory",
    type: :object,
    properties: %{
      workspace_devices: %OpenApiSpex.Schema{
        type: :array,
        items: %OpenApiSpex.Schema{type: :object}
      },
      share_participant_devices: %OpenApiSpex.Schema{
        type: :array,
        items: %OpenApiSpex.Schema{type: :object}
      }
    },
    required: [:workspace_devices, :share_participant_devices]
  })
end

defmodule RefMDWeb.Schemas.ShareDocumentBootstrapResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareDocumentBootstrapResponse",
    type: :object,
    properties: %{
      share_slug: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      title: %Schema{type: :string, nullable: true},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      verification_directory: RefMDWeb.Schemas.ShareVerificationDirectory
    },
    required: [
      :share_slug,
      :share_id,
      :document_id,
      :workspace_id,
      :title,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :permission,
      :password_protected,
      :encrypted_dek,
      :nonce,
      :verification_directory
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareDocumentBootstrapRequiredResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareDocumentBootstrapRequiredResponse",
    type: :object,
    properties: %{
      share_slug: %Schema{type: :string},
      bootstrap_required: %Schema{type: :boolean}
    },
    required: [:share_slug, :bootstrap_required]
  })
end

defmodule RefMDWeb.Schemas.ShareTreeEntry do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareTreeEntry",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer, nullable: true},
      title: %Schema{type: :string, nullable: true},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      document_token: %Schema{type: :string, nullable: true},
      folder_token: %Schema{type: :string, nullable: true}
    },
    required: [
      :id,
      :share_id,
      :doc_type,
      :parent_id,
      :position,
      :title,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :encrypted_dek,
      :nonce,
      :document_token,
      :folder_token
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareFolderBootstrapResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareFolderBootstrapResponse",
    type: :object,
    properties: %{
      share_slug: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid},
      password_protected: %Schema{type: :boolean},
      verification_directory: RefMDWeb.Schemas.ShareVerificationDirectory,
      folder: RefMDWeb.Schemas.ShareTreeEntry,
      entries: %Schema{type: :array, items: RefMDWeb.Schemas.ShareTreeEntry}
    },
    required: [
      :share_slug,
      :share_id,
      :password_protected,
      :verification_directory,
      :folder,
      :entries
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateShareMountRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateShareMountRequest",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      share_slug: %Schema{type: :string},
      target_kind: %Schema{type: :string, enum: ["document", "folder"]},
      target_token: %Schema{type: :string},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true}
    },
    required: [:workspace_id, :share_slug, :target_kind, :target_token]
  })
end

defmodule RefMDWeb.Schemas.UpdateShareMountRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateShareMountRequest",
    type: :object,
    properties: %{
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer}
    },
    required: [:position]
  })
end

defmodule RefMDWeb.Schemas.ShareMountTarget do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountTarget",
    type: :object,
    properties: %{
      document_id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      title: %Schema{type: :string, nullable: true},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true}
    },
    required: [
      :document_id,
      :doc_type,
      :title,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareMountShareSummary do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountShareSummary",
    type: :object,
    properties: %{
      scope: %Schema{type: :string, enum: ["document", "folder"]},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      document_id: %Schema{type: :string, format: :uuid}
    },
    required: [:scope, :permission, :document_id]
  })
end

defmodule RefMDWeb.Schemas.ShareMountResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      target_kind: %Schema{type: :string, enum: ["document", "folder"]},
      target_token: %Schema{type: :string, nullable: true},
      target_document_id: %Schema{type: :string, format: :uuid},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer},
      status: %Schema{type: :string, enum: ["active", "expired", "access_limit_reached"]},
      password_protected: %Schema{type: :boolean},
      share: RefMDWeb.Schemas.ShareMountShareSummary,
      target: RefMDWeb.Schemas.ShareMountTarget,
      title: %Schema{type: :string, nullable: true},
      title_state: %Schema{type: :string}
    },
    required: [
      :id,
      :workspace_id,
      :share_id,
      :target_kind,
      :target_token,
      :target_document_id,
      :parent_id,
      :position,
      :status,
      :password_protected,
      :share,
      :target,
      :title,
      :title_state
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareMountCreateResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountCreateResponse",
    allOf: [RefMDWeb.Schemas.ShareMountResponse]
  })
end

defmodule RefMDWeb.Schemas.ShareMountConflictResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountConflictResponse",
    type: :object,
    properties: %{
      mount: RefMDWeb.Schemas.ShareMountResponse
    },
    required: [:mount]
  })
end

defmodule RefMDWeb.Schemas.ShareMountLookupItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountLookupItem",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      target_kind: %Schema{type: :string, enum: ["document", "folder"]},
      target_token: %Schema{type: :string}
    },
    required: [:id, :workspace_id, :share_id, :target_kind, :target_token]
  })
end

defmodule RefMDWeb.Schemas.ShareMountLookupResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountLookupResponse",
    type: :object,
    properties: %{
      mounts: %Schema{type: :array, items: RefMDWeb.Schemas.ShareMountLookupItem}
    },
    required: [:mounts]
  })
end

defmodule RefMDWeb.Schemas.ShareMountListResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountListResponse",
    type: :object,
    properties: %{
      mounts: %Schema{type: :array, items: RefMDWeb.Schemas.ShareMountResponse}
    },
    required: [:mounts]
  })
end

defmodule RefMDWeb.Schemas.ShareMountChildShare do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountChildShare",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      document_token: %Schema{type: :string, nullable: true},
      folder_token: %Schema{type: :string, nullable: true}
    },
    required: [:share_id, :document_id, :doc_type, :document_token, :folder_token]
  })
end

defmodule RefMDWeb.Schemas.ShareMountDetailResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountDetailResponse",
    type: :object,
    properties: %{
      mount: RefMDWeb.Schemas.ShareMountResponse,
      admission: %Schema{allOf: [RefMDWeb.Schemas.MountedShareAdmission], nullable: true},
      folder_tree: %Schema{
        type: :object,
        nullable: true,
        properties: %{
          folder: RefMDWeb.Schemas.ShareTreeEntry,
          entries: %Schema{type: :array, items: RefMDWeb.Schemas.ShareTreeEntry}
        }
      },
      child_shares: %Schema{
        type: :array,
        nullable: true,
        items: RefMDWeb.Schemas.ShareMountChildShare
      }
    },
    required: [:mount, :admission, :folder_tree, :child_shares]
  })
end

defmodule RefMDWeb.Schemas.ShareMountFolderMountSummary do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountFolderMountSummary",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      status: %Schema{type: :string, enum: ["active"]}
    },
    required: [:id, :share_id, :status]
  })
end

defmodule RefMDWeb.Schemas.ShareMountFolderResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountFolderResponse",
    type: :object,
    properties: %{
      mount: RefMDWeb.Schemas.ShareMountFolderMountSummary,
      folder: RefMDWeb.Schemas.ShareTreeEntry,
      entries: %Schema{type: :array, items: RefMDWeb.Schemas.ShareTreeEntry}
    },
    required: [:mount, :folder, :entries]
  })
end

defmodule RefMDWeb.Schemas.MountedShareAdmission do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MountedShareAdmission",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      title: %Schema{type: :string, nullable: true},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      verification_directory: RefMDWeb.Schemas.ShareVerificationDirectory
    },
    required: [
      :share_id,
      :document_id,
      :workspace_id,
      :title,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :permission,
      :password_protected,
      :encrypted_dek,
      :nonce,
      :verification_directory
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareMountChallengeRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountChallengeRequest",
    type: :object,
    properties: %{
      response: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid, nullable: true},
      document_id: %Schema{type: :string, format: :uuid, nullable: true}
    },
    required: [:response]
  })
end

defmodule RefMDWeb.Schemas.ShareMountDocumentChallengeResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountDocumentChallengeResponse",
    type: :object,
    properties: %{
      admission: RefMDWeb.Schemas.MountedShareAdmission
    },
    required: [:admission]
  })
end

defmodule RefMDWeb.Schemas.ShareMountFolderChallengeResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountFolderChallengeResponse",
    type: :object,
    properties: %{
      mount: RefMDWeb.Schemas.ShareMountResponse,
      folder_tree: %OpenApiSpex.Schema{
        type: :object,
        properties: %{
          folder: RefMDWeb.Schemas.ShareTreeEntry,
          entries: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.ShareTreeEntry}
        },
        required: [:folder, :entries]
      },
      child_shares: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.ShareMountChildShare
      }
    },
    required: [:mount, :folder_tree, :child_shares]
  })
end
