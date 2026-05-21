defmodule RefMDWeb.Schemas.ShareVerificationWorkspaceDevice do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareVerificationWorkspaceDevice",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      user_id: %Schema{type: :string, format: :uuid},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      hybrid_encryption_public_key_material: RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      encryption_key_id: %Schema{type: :string},
      identity_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      identity_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      approval_signature: RefMDWeb.Schemas.HybridSignature,
      approval_signature_surface: %Schema{
        type: :string,
        enum: ["genesis_device_bootstrap", "device_approval", "recovery_device_approval"]
      },
      approval_proof: RefMDWeb.Schemas.DeviceApprovalProof,
      approval_delivery_commitments: %Schema{
        allOf: [RefMDWeb.Schemas.ApprovalDeliveryCommitments],
        nullable: true
      },
      approval_delivery_artifacts: %Schema{
        allOf: [RefMDWeb.Schemas.ApprovalDeliveryArtifacts],
        nullable: true
      },
      client_nonce: %Schema{type: :string},
      historical: %Schema{type: :boolean}
    },
    required: [
      :device_id,
      :user_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :identity_hybrid_signing_public_key_material,
      :identity_hybrid_encryption_public_key_material,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :client_nonce,
      :historical
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareVerificationParticipantDevice do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareVerificationParticipantDevice",
    type: :object,
    properties: %{
      share_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_session_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_token_hash: %Schema{type: :string, nullable: true},
      share_permission: %Schema{type: :string, enum: ["view", "edit"], nullable: true},
      share_password_protected: %Schema{type: :boolean, nullable: true},
      share_scope_kind: %Schema{type: :string, enum: ["document", "folder"], nullable: true},
      share_scope_id: %Schema{type: :string, nullable: true},
      share_created_event_hash: %Schema{type: :string, nullable: true},
      share_latest_bootstrap_event_hash: %Schema{type: :string, nullable: true},
      share_capability_context_hash: %Schema{type: :string, nullable: true},
      share_capability_secret_commitment: %Schema{type: :string, nullable: true},
      authorization_public_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.ShareCapabilitySigningPublicKeyMaterial],
        nullable: true
      },
      device_id: %Schema{type: :string, format: :uuid},
      principal_id: %Schema{type: :string, format: :uuid},
      display_name: %Schema{type: :string, nullable: true},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      hybrid_encryption_public_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial],
        nullable: true
      },
      encryption_key_id: %Schema{type: :string, nullable: true},
      participant_device_kind: %Schema{
        type: :string,
        enum: ["share_participant_device"]
      },
      identity_hybrid_signing_public_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.HybridSigningPublicKeyMaterial],
        nullable: true
      },
      identity_hybrid_encryption_public_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial],
        nullable: true
      },
      approval_signature: %Schema{
        allOf: [RefMDWeb.Schemas.HybridSignature],
        nullable: true
      },
      approval_signature_surface: %Schema{type: :string, nullable: true},
      approval_proof: %Schema{
        allOf: [RefMDWeb.Schemas.DeviceApprovalProof],
        nullable: true
      },
      approval_delivery_commitments: %Schema{
        allOf: [RefMDWeb.Schemas.ApprovalDeliveryCommitments],
        nullable: true
      },
      approval_delivery_artifacts: %Schema{
        allOf: [RefMDWeb.Schemas.ApprovalDeliveryArtifacts],
        nullable: true
      },
      client_nonce: %Schema{type: :string, nullable: true},
      historical: %Schema{type: :boolean}
    },
    required: [
      :share_id,
      :share_session_id,
      :device_id,
      :principal_id,
      :display_name,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :participant_device_kind,
      :historical
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareVerificationDirectory do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareVerificationDirectory",
    type: :object,
    properties: %{
      workspace_devices: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.ShareVerificationWorkspaceDevice
      },
      share_participant_devices: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.ShareVerificationParticipantDevice
      }
    },
    required: [:workspace_devices, :share_participant_devices]
  })
end
