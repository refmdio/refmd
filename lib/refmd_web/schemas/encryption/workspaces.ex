defmodule RefMDWeb.Schemas.WorkspaceIdsResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceIdsResponse",
    type: :object,
    properties: %{
      workspace_ids: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}}
    },
    required: [:workspace_ids]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceAuditCheckpoint do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceAuditCheckpoint",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      audit_checkpoint: RefMDWeb.Schemas.AuditCheckpoint
    },
    required: [:workspace_id, :audit_checkpoint]
  })
end

defmodule RefMDWeb.Schemas.EncryptionSetupCompleteResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "EncryptionSetupCompleteResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      ok: %Schema{type: :boolean, enum: [true]},
      user_audit_checkpoint: RefMDWeb.Schemas.AuditCheckpoint,
      workspace_audit_checkpoints: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceAuditCheckpoint
      }
    },
    required: [:ok, :user_audit_checkpoint, :workspace_audit_checkpoints]
  })
end

defmodule RefMDWeb.Schemas.CreateWorkspaceKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @wrap_properties RefMDWeb.Schemas.HybridKeyWrapFields.schema().properties
  @wrap_required RefMDWeb.Schemas.HybridKeyWrapFields.schema().required

  OpenApiSpex.schema(%{
    title: "CreateWorkspaceKeyRequest",
    type: :object,
    additionalProperties: false,
    properties:
      Map.merge(@wrap_properties, %{
        target_user_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid},
        key_version: %Schema{type: :integer},
        sender_device_id: %Schema{type: :string, format: :uuid},
        is_active: %Schema{type: :boolean},
        workspace_key_directory_events: %Schema{
          type: :array,
          items: RefMDWeb.Schemas.KeyDirectoryEnvelope
        },
        workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
      }),
    required:
      @wrap_required ++
        [
          :target_user_id,
          :device_id,
          :key_version,
          :sender_device_id,
          :workspace_key_directory_events,
          :workspace_key_directory_checkpoint
        ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceKeyItem",
    allOf: [
      RefMDWeb.Schemas.HybridKeyWrapFields,
      %Schema{
        type: :object,
        properties: %{
          key_version: %Schema{type: :integer},
          is_active: %Schema{type: :boolean},
          sender_device_id: %Schema{type: :string, format: :uuid},
          sender_user_id: %Schema{type: :string, format: :uuid},
          sender_hybrid_encryption_public_key_material:
            RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
          sender_hybrid_signing_public_key_material:
            RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
          sender_identity_hybrid_encryption_public_key_material:
            RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
          sender_identity_hybrid_signing_public_key_material:
            RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
          sender_approval_signature: RefMDWeb.Schemas.HybridSignature,
          sender_approval_signature_surface: %Schema{
            type: :string,
            enum: ["genesis_device_bootstrap", "device_approval", "recovery_device_approval"]
          },
          sender_approval_proof: RefMDWeb.Schemas.DeviceApprovalProof,
          sender_approval_delivery_commitments: %Schema{
            allOf: [RefMDWeb.Schemas.ApprovalDeliveryCommitments],
            nullable: true
          },
          sender_approval_delivery_artifacts: %Schema{
            allOf: [RefMDWeb.Schemas.ApprovalDeliveryArtifacts],
            nullable: true
          },
          sender_client_nonce: %Schema{type: :string},
          workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
          workspace_key_directory_checkpoint_ancestry: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          workspace_key_directory_event_ancestry: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          }
        },
        required: [
          :key_version,
          :is_active,
          :sender_device_id,
          :sender_user_id,
          :sender_hybrid_encryption_public_key_material,
          :sender_hybrid_signing_public_key_material,
          :sender_identity_hybrid_encryption_public_key_material,
          :sender_identity_hybrid_signing_public_key_material,
          :sender_approval_signature,
          :sender_approval_signature_surface,
          :sender_approval_proof,
          :sender_approval_delivery_commitments,
          :sender_approval_delivery_artifacts,
          :sender_client_nonce,
          :workspace_key_directory_checkpoint,
          :workspace_key_directory_checkpoint_ancestry,
          :workspace_key_directory_event_ancestry
        ]
      }
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceKeysResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceKeysResponse",
    type: :object,
    properties: %{
      current_kek_version: %Schema{type: :integer},
      keys: %Schema{type: :array, items: RefMDWeb.Schemas.WorkspaceKeyItem}
    },
    required: [:current_kek_version, :keys]
  })
end
