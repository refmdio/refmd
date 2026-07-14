defmodule RefMDWeb.Schemas.RecoveryDataResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecoveryDataResponse",
    type: :object,
    properties: %{
      recovery_encrypted_umk: %Schema{type: :string},
      recovery_nonce: %Schema{type: :string},
      encrypted_identity_hybrid_encryption_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_encryption_private_key_material_nonce:
        RefMDWeb.Schemas.EncryptedMaterialNonce,
      identity_encryption_key_id: %Schema{type: :string},
      encrypted_identity_hybrid_signing_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_signing_private_key_material_nonce: RefMDWeb.Schemas.EncryptedMaterialNonce,
      identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      identity_rotation_due_at: %Schema{type: :string, format: :"date-time", nullable: true},
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial,
      hybrid_signing_public_key_material: RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      candidate_user_checkpoint_sequence: %Schema{type: :integer},
      candidate_user_checkpoint_hash: %Schema{type: :string},
      candidate_user_event_head_sequence: %Schema{type: :integer},
      candidate_user_event_head_hash: %Schema{type: :string},
      candidate_user_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      candidate_user_checkpoint_ancestry: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      candidate_user_event_ancestry: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      candidate_user_rotation_deletion_evidences: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.IdentityRotationDeletionEvidence
      },
      candidate_user_audit_checkpoint: RefMDWeb.Schemas.AuditCheckpoint,
      candidate_workspace_checkpoints: %Schema{
        type: :array,
        items: %Schema{
          type: :object,
          additionalProperties: false,
          properties: %{
            workspace_id: %Schema{type: :string, format: :uuid},
            checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
            checkpoint_ancestry: %Schema{
              type: :array,
              items: RefMDWeb.Schemas.KeyDirectoryEnvelope
            },
            event_ancestry: %Schema{
              type: :array,
              items: RefMDWeb.Schemas.KeyDirectoryEnvelope
            }
          },
          required: [:workspace_id, :checkpoint]
        }
      }
    },
    required: [
      :recovery_encrypted_umk,
      :recovery_nonce,
      :identity_rotation_due_at,
      :candidate_user_rotation_deletion_evidences
    ]
  })
end

defmodule RefMDWeb.Schemas.RecoveryChallengeRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecoveryChallengeRequest",
    type: :object,
    properties: %{
      email: %Schema{type: :string, format: :email}
    },
    required: [:email]
  })
end

defmodule RefMDWeb.Schemas.RecoveryChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecoveryChallengeResponse",
    type: :object,
    properties: %{
      challenge: %Schema{type: :string}
    },
    required: [:challenge]
  })
end

defmodule RefMDWeb.Schemas.RecoverySessionRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @target_device_registration %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string, enum: ["browser", "desktop", "mobile"]},
      identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      device_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      device_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      device_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
      device_encryption_key_id: %Schema{type: :string},
      client_nonce: %Schema{type: :string}
    },
    required: [
      :device_id,
      :identity_signing_key_id,
      :device_hybrid_signing_public_key_material,
      :device_signing_key_id,
      :device_hybrid_encryption_public_key_material,
      :device_encryption_key_id,
      :client_nonce
    ]
  }

  OpenApiSpex.schema(%{
    title: "RecoverySessionRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      email: %Schema{type: :string, format: :email},
      recovery_session_id: %Schema{type: :string, format: :uuid},
      challenge: %Schema{type: :string},
      recovery_session_signature: RefMDWeb.Schemas.HybridSignature,
      recovery_authorization_key_id: %Schema{type: :string},
      recovery_authorization_proof: RefMDWeb.Schemas.HybridSignature,
      recovery_capability_hash: %Schema{type: :string},
      recovery_session_transcript_hash: %Schema{type: :string},
      pending_registration_id: %Schema{type: :string, format: :uuid},
      recipient_device_id: %Schema{type: :string, format: :uuid},
      pending_registration_binding_hash: %Schema{type: :string},
      target_key_checkpoint_sequence: %Schema{type: :integer},
      target_key_checkpoint_hash: %Schema{type: :string},
      candidate_user_checkpoint_sequence: %Schema{type: :integer},
      candidate_user_checkpoint_hash: %Schema{type: :string},
      candidate_user_event_head_sequence: %Schema{type: :integer},
      candidate_user_event_head_hash: %Schema{type: :string},
      candidate_user_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      candidate_user_event_ancestry: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      candidate_user_audit_sequence: %Schema{type: :integer},
      candidate_user_audit_hash: RefMDWeb.Schemas.Blake3Base64Url,
      target_device_registration: @target_device_registration
    },
    required: [
      :email,
      :recovery_session_id,
      :challenge,
      :recovery_session_signature,
      :recovery_authorization_key_id,
      :recovery_authorization_proof,
      :recovery_capability_hash,
      :recovery_session_transcript_hash,
      :pending_registration_id,
      :recipient_device_id,
      :pending_registration_binding_hash,
      :target_key_checkpoint_sequence,
      :target_key_checkpoint_hash,
      :candidate_user_checkpoint_sequence,
      :candidate_user_checkpoint_hash,
      :candidate_user_event_head_sequence,
      :candidate_user_event_head_hash,
      :candidate_user_checkpoint,
      :candidate_user_event_ancestry,
      :candidate_user_audit_sequence,
      :candidate_user_audit_hash,
      :target_device_registration
    ]
  })
end

defmodule RefMDWeb.Schemas.RecoverySessionResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecoverySessionResponse",
    type: :object,
    properties: %{
      user: RefMDWeb.Schemas.UserInfo,
      session_id: %Schema{type: :string, format: :uuid},
      is_recovery: %Schema{type: :boolean},
      audit_checkpoint: RefMDWeb.Schemas.AuditCheckpoint
    },
    required: [:user, :session_id, :is_recovery, :audit_checkpoint]
  })
end
