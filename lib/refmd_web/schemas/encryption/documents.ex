defmodule RefMDWeb.Schemas.CreateDocumentKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDocumentKeyRequest",
    type: :object,
    properties: %{
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      key_version: %Schema{type: :integer, minimum: 1},
      kek_version: %Schema{type: :integer, minimum: 1},
      dek_rotation_start_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      dek_rotation_start_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      share_key_replacements: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.DocumentShareKeyRotationReplacement
      },
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [:encrypted_dek, :nonce, :key_version, :kek_version]
  })
end

defmodule RefMDWeb.Schemas.RewrapDocumentKeyForKekRotationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RewrapDocumentKeyForKekRotationRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      key_version: %Schema{type: :integer, minimum: 1},
      new_kek_version: %Schema{type: :integer, minimum: 2}
    },
    required: [:encrypted_dek, :nonce, :key_version, :new_kek_version]
  })
end

defmodule RefMDWeb.Schemas.DocumentShareKeyRotationReplacement do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentShareKeyRotationReplacement",
    type: :object,
    additionalProperties: false,
    properties: %{
      root_share_id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer, minimum: 1},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:root_share_id, :share_id, :document_id, :key_version, :encrypted_dek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeyRotationTarget do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeyRotationTarget",
    type: :object,
    properties: %{
      root_share_id: %Schema{type: :string, format: :uuid},
      root_document_id: %Schema{type: :string, format: :uuid},
      target_share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      current_key_version: %Schema{type: :integer, minimum: 1},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      max_views: %Schema{type: :integer, minimum: 1},
      expires_event_sequence: %Schema{type: :integer, minimum: 1},
      share_link_secret_backup_wraps: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceOperationProvenSignedPqWrap
      }
    },
    required: [
      :root_share_id,
      :root_document_id,
      :target_share_id,
      :document_id,
      :current_key_version,
      :permission,
      :password_protected,
      :max_views,
      :expires_event_sequence,
      :share_link_secret_backup_wraps
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeyRotationTargetsResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeyRotationTargetsResponse",
    type: :object,
    properties: %{
      current_key_version: %Schema{type: :integer, minimum: 1},
      targets: %Schema{type: :array, items: RefMDWeb.Schemas.DocumentKeyRotationTarget}
    },
    required: [:current_key_version, :targets]
  })
end

defmodule RefMDWeb.Schemas.DekRotationCompletionRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DekRotationCompletionRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      new_key_version: %Schema{type: :integer, minimum: 2},
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      device_key_deletion_proofs: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.DeviceKeyDeletionProof
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :new_key_version,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ]
  })
end

defmodule RefMDWeb.Schemas.DekRotationCompletionManifestResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DekRotationCompletionManifestResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_version: %Schema{type: :integer, minimum: 1},
      new_key_version: %Schema{type: :integer, minimum: 2},
      started_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      completed_at_event_sequence: %Schema{type: :integer, minimum: 1},
      deleted_at_event_sequence: %Schema{type: :integer, minimum: 1},
      server_rejects_old_key_uploads_after_sequence: %Schema{type: :integer, minimum: 1},
      completion_manifest_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_wrap_ids_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :old_key_version,
      :new_key_version,
      :started_event_hash,
      :completed_at_event_sequence,
      :deleted_at_event_sequence,
      :server_rejects_old_key_uploads_after_sequence,
      :completion_manifest_hash,
      :deleted_secret_ids_hash,
      :deleted_wrap_ids_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentWipeRequirementResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentWipeRequirementResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      required_dek_version: %Schema{type: :integer, minimum: 2},
      old_key_version: %Schema{type: :integer, minimum: 1},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :workspace_id,
      :required_dek_version,
      :old_key_version,
      :rotation_completed_event_hash,
      :deleted_secret_ids_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentWipeAcknowledgementRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentWipeAcknowledgementRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      device_key_deletion_proof: RefMDWeb.Schemas.DeviceKeyDeletionProof
    },
    required: [:device_key_deletion_proof]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeyResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeyResponse",
    type: :object,
    properties: %{
      document_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      kek_version: %Schema{type: :integer},
      is_active: %Schema{type: :boolean},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :document_id,
      :key_version,
      :encrypted_dek,
      :nonce,
      :kek_version,
      :is_active,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeysResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeysResponse",
    type: :object,
    properties: %{
      keys: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.DocumentKeyResponse
      }
    },
    required: [:keys]
  })
end
