defmodule RefMDWeb.Schemas.MemberEnvelopeItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @wrap_properties RefMDWeb.Schemas.HybridKeyWrapFields.schema().properties
  @wrap_required RefMDWeb.Schemas.HybridKeyWrapFields.schema().required

  OpenApiSpex.schema(%{
    title: "MemberEnvelopeItem",
    type: :object,
    additionalProperties: false,
    properties:
      Map.merge(@wrap_properties, %{
        target_user_id: %Schema{type: :string, format: :uuid},
        key_version: %Schema{type: :integer},
        sender_device_id: %Schema{type: :string, format: :uuid}
      }),
    required: @wrap_required ++ [:target_user_id, :key_version, :sender_device_id]
  })
end

defmodule RefMDWeb.Schemas.SaveMemberEnvelopesRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SaveMemberEnvelopesRequest",
    type: :object,
    properties: %{
      envelopes: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.MemberEnvelopeItem},
      workspace_key_directory_events: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [:envelopes, :workspace_key_directory_events, :workspace_key_directory_checkpoint]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceMemberKeysResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceMemberKeysResponse",
    type: :object,
    properties: %{
      members: %Schema{
        type: :array,
        items: %Schema{
          type: :object,
          properties: %{
            user_id: %Schema{type: :string, format: :uuid},
            hybrid_encryption_public_key_material:
              RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
            hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial
          },
          required: [
            :user_id,
            :hybrid_encryption_public_key_material,
            :hybrid_signing_public_key_material
          ]
        }
      }
    },
    required: [:members]
  })
end

defmodule RefMDWeb.Schemas.MemberEnvelopeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberEnvelopeResponse",
    allOf: [
      RefMDWeb.Schemas.HybridKeyWrapFields,
      %Schema{
        type: :object,
        properties: %{
          key_version: %Schema{type: :integer},
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
