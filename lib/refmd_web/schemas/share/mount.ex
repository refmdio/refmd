defmodule RefMDWeb.Schemas.CreateShareMountRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateShareMountRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      share_slug: %Schema{type: :string},
      target_kind: %Schema{type: :string, enum: ["document", "folder"]},
      target_token: %Schema{type: :string},
      authenticated_workspace_pin_bootstrap_hash: RefMDWeb.Schemas.Blake3Base64Url,
      parent_id: %Schema{type: :string, format: :uuid, nullable: true}
    },
    required: [
      :workspace_id,
      :share_slug,
      :target_kind,
      :target_token,
      :authenticated_workspace_pin_bootstrap_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.UpdateShareMountRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateShareMountRequest",
    type: :object,
    additionalProperties: false,
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
    additionalProperties: false,
    properties: %{
      document_id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]}
    },
    required: [
      :document_id,
      :doc_type
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
      status: %Schema{type: :string, enum: ["active", "expired"]},
      password_protected: %Schema{type: :boolean},
      share: RefMDWeb.Schemas.ShareMountShareSummary,
      target: RefMDWeb.Schemas.ShareMountTarget
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
      :target
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

defmodule RefMDWeb.Schemas.ShareMountListResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountListResponse",
    type: :object,
    properties: %{
      mounts: %Schema{type: :array, items: RefMDWeb.Schemas.ShareMountListItem}
    },
    required: [:mounts]
  })
end

defmodule RefMDWeb.Schemas.ShareMountListItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountListItem",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      target_kind: %Schema{type: :string, enum: ["document", "folder"]},
      target_token: %Schema{type: :string, nullable: true},
      target_document_id: %Schema{type: :string, format: :uuid},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer},
      status: %Schema{type: :string, enum: ["active", "expired"]},
      password_protected: %Schema{type: :boolean},
      share: RefMDWeb.Schemas.ShareMountShareSummary,
      target: RefMDWeb.Schemas.ShareMountTarget
    },
    required: [
      :id,
      :share_id,
      :target_kind,
      :target_token,
      :target_document_id,
      :parent_id,
      :position,
      :status,
      :password_protected,
      :share,
      :target
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareLinkMountListItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareLinkMountListItem",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      target_kind: %Schema{type: :string, enum: ["document", "folder"]},
      target_token: %Schema{type: :string, nullable: true}
    },
    required: [:id, :workspace_id, :share_id, :target_kind, :target_token]
  })
end

defmodule RefMDWeb.Schemas.ShareLinkMountListResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareLinkMountListResponse",
    type: :object,
    properties: %{
      mounts: %Schema{type: :array, items: RefMDWeb.Schemas.ShareLinkMountListItem}
    },
    required: [:mounts]
  })
end

defmodule RefMDWeb.Schemas.ShareMountMetadataResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountMetadataResponse",
    type: :object,
    properties: %{
      mount: RefMDWeb.Schemas.ShareMountResponse,
      bootstrap_required: %Schema{type: :boolean}
    },
    required: [:mount, :bootstrap_required]
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
      workspace_id: %Schema{type: :string, format: :uuid},
      status: %Schema{type: :string, enum: ["active"]}
    },
    required: [:id, :share_id, :workspace_id, :status]
  })
end

defmodule RefMDWeb.Schemas.ShareMountBootstrapMountSummary do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountBootstrapMountSummary",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      status: %Schema{type: :string, enum: ["active"]}
    },
    required: [:id, :share_id, :status]
  })
end

defmodule RefMDWeb.Schemas.MountedShareTreeEntry do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MountedShareTreeEntry",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer, nullable: true},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      workspace_pin_bootstrap: %Schema{
        allOf: [RefMDWeb.Schemas.WorkspacePinBootstrap],
        nullable: true
      },
      document_token: %Schema{type: :string, nullable: true},
      folder_token: %Schema{type: :string, nullable: true}
    },
    required: [
      :id,
      :share_id,
      :doc_type,
      :parent_id,
      :position,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :encrypted_dek,
      :nonce,
      :workspace_pin_bootstrap,
      :document_token,
      :folder_token
    ]
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
      folder: RefMDWeb.Schemas.MountedShareTreeEntry,
      entries: %Schema{type: :array, items: RefMDWeb.Schemas.MountedShareTreeEntry}
    },
    required: [:mount, :folder, :entries]
  })
end

defmodule RefMDWeb.Schemas.MountedShareDocument do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MountedShareDocument",
    type: :object,
    additionalProperties: false,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid},
      authorization_share_id: %Schema{type: :string, format: :uuid},
      document_token: %Schema{type: :string},
      document_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      verification_directory: RefMDWeb.Schemas.ShareVerificationDirectory,
      workspace_pin_bootstrap: %Schema{
        allOf: [RefMDWeb.Schemas.WorkspacePinBootstrap],
        nullable: true
      },
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      }
    },
    required: [
      :share_id,
      :authorization_share_id,
      :document_token,
      :document_id,
      :workspace_id,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :permission,
      :password_protected,
      :encrypted_dek,
      :nonce,
      :verification_directory,
      :workspace_pin_bootstrap,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareMountDocumentResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountDocumentResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      mount: RefMDWeb.Schemas.ShareMountBootstrapMountSummary,
      document: RefMDWeb.Schemas.MountedShareDocument
    },
    required: [:mount, :document]
  })
end

defmodule RefMDWeb.Schemas.ShareMountChallengeRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountChallengeRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      response: %Schema{type: :string},
      password_challenge_hash: %Schema{type: :string}
    },
    required: [:response, :password_challenge_hash]
  })
end

defmodule RefMDWeb.Schemas.ShareMountBootstrapRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountBootstrapRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      authenticated_workspace_pin_bootstrap_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :authenticated_workspace_pin_bootstrap_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareMountChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareMountChallengeResponse",
    type: :object,
    properties: %{
      mount_id: %Schema{type: :string, format: :uuid},
      bootstrap_required: %Schema{type: :boolean}
    },
    required: [:mount_id, :bootstrap_required]
  })
end
