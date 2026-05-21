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
          sender_client_nonce: %Schema{type: :string}
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
          :sender_client_nonce
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
