defmodule RefMDWeb.Schemas.WorkspaceInvitationDeliveryTargetRegistration do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceInvitationDeliveryTargetRegistration",
    type: :object,
    additionalProperties: false,
    properties: %{
      identity_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      identity_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      device_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      device_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial
    },
    required: [
      :identity_hybrid_encryption_public_key_material,
      :identity_hybrid_signing_public_key_material,
      :device_hybrid_encryption_public_key_material,
      :device_hybrid_signing_public_key_material
    ]
  })
end

defmodule RefMDWeb.Schemas.GuestInvitationDeliveryTargetRegistration do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GuestInvitationDeliveryTargetRegistration",
    type: :object,
    additionalProperties: false,
    properties: %{
      identity_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      identity_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      device_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      device_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      recoverable_identity_secret_record: RefMDWeb.Schemas.RecoverableIdentitySecretRecord,
      user_key_directory_events: %Schema{
        type: :array,
        minItems: 1,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :identity_hybrid_encryption_public_key_material,
      :identity_hybrid_signing_public_key_material,
      :device_hybrid_encryption_public_key_material,
      :device_hybrid_signing_public_key_material,
      :recoverable_identity_secret_record,
      :user_key_directory_events,
      :user_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationDeliveryTargetRegistration do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationDeliveryTargetRegistration",
    oneOf: [
      RefMDWeb.Schemas.WorkspaceInvitationDeliveryTargetRegistration,
      RefMDWeb.Schemas.GuestInvitationDeliveryTargetRegistration
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationDeliveryTargetRegistrationProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationDeliveryTargetRegistrationProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      client_nonce: %Schema{type: :string},
      device_name: %Schema{type: :string},
      device_type: %Schema{type: :string}
    },
    required: [
      :client_nonce,
      :device_name,
      :device_type
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateInvitationDeliveryAttemptRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateInvitationDeliveryAttemptRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      token: %Schema{type: :string},
      redeem_attempt_id: %Schema{type: :string, format: :uuid},
      target_user_id: %Schema{type: :string, format: :uuid},
      target_device_id: %Schema{type: :string, format: :uuid},
      target_registration: RefMDWeb.Schemas.InvitationDeliveryTargetRegistration,
      target_registration_proof: RefMDWeb.Schemas.InvitationDeliveryTargetRegistrationProof,
      recipient_redeem_nonce: %Schema{type: :string},
      live_redeem_challenge_hash: %Schema{type: :string}
    },
    required: [
      :token,
      :redeem_attempt_id,
      :target_user_id,
      :target_device_id,
      :target_registration,
      :recipient_redeem_nonce,
      :live_redeem_challenge_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationDeliveryAttemptResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationDeliveryAttemptResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      redeem_attempt_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      context_kind: %Schema{
        type: :string,
        enum: ["workspace_invitation", "guest_invitation"]
      },
      context_id: %Schema{type: :string, format: :uuid},
      recipient_user_id: %Schema{type: :string, format: :uuid},
      recipient_device_id: %Schema{type: :string, format: :uuid},
      target_user_id: %Schema{type: :string, format: :uuid},
      target_device_id: %Schema{type: :string, format: :uuid},
      target_encryption_key_id: %Schema{type: :string},
      target_key_checkpoint_sequence: %Schema{type: :integer, nullable: true},
      target_key_checkpoint_hash: %Schema{type: :string, nullable: true},
      target_registration: RefMDWeb.Schemas.InvitationDeliveryTargetRegistration,
      target_registration_proof: %Schema{
        allOf: [RefMDWeb.Schemas.InvitationDeliveryTargetRegistrationProof],
        nullable: true
      },
      recipient_redeem_nonce: %Schema{type: :string},
      live_redeem_challenge_hash: %Schema{type: :string},
      recipient_nonce_state_hash: %Schema{type: :string},
      request_binding_hash: %Schema{type: :string},
      resource_hash: %Schema{type: :string},
      context_snapshot: %Schema{type: :object},
      status: %Schema{type: :string, enum: ["pending", "approved", "consumed", "expired"]},
      authorization_id: %Schema{type: :string, format: :uuid, nullable: true},
      approved_artifacts: %Schema{type: :object, nullable: true},
      expires_at: %Schema{type: :string, format: :date_time},
      created_at: %Schema{type: :string, format: :date_time}
    },
    required: [
      :redeem_attempt_id,
      :workspace_id,
      :context_kind,
      :context_id,
      :recipient_user_id,
      :recipient_device_id,
      :target_user_id,
      :target_device_id,
      :target_encryption_key_id,
      :target_registration,
      :recipient_redeem_nonce,
      :live_redeem_challenge_hash,
      :recipient_nonce_state_hash,
      :request_binding_hash,
      :resource_hash,
      :context_snapshot,
      :status,
      :expires_at,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationDeliveryAttemptListResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationDeliveryAttemptListResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      attempts: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.InvitationDeliveryAttemptResponse
      }
    },
    required: [:attempts]
  })
end

defmodule RefMDWeb.Schemas.RecipientBoundAuthorizationRecipient do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecipientBoundAuthorizationRecipient",
    type: :object,
    additionalProperties: false,
    properties: %{
      recipient_kind: %Schema{type: :string, enum: ["invitee", "guest"]},
      recipient_principal_id: %Schema{type: :string, format: :uuid},
      recipient_device_id: %Schema{type: :string, format: :uuid},
      encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :recipient_kind,
      :recipient_principal_id,
      :recipient_device_id,
      :encryption_key_id
    ]
  })
end

defmodule RefMDWeb.Schemas.RecipientBoundAuthorizationPayload do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecipientBoundAuthorizationPayload",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.recipient-bound-authorization"]},
      version: %Schema{type: :integer, enum: [1]},
      authorization_id: %Schema{type: :string, format: :uuid},
      redeem_attempt_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      context_kind: %Schema{
        type: :string,
        enum: ["workspace_invitation", "guest_invitation"]
      },
      context_id: %Schema{type: :string, format: :uuid},
      resource_hash: RefMDWeb.Schemas.Blake3Base64Url,
      recipient: RefMDWeb.Schemas.RecipientBoundAuthorizationRecipient,
      workspace_pin_bootstrap_hash: RefMDWeb.Schemas.Blake3Base64Url,
      current_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      current_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      current_event_head_sequence: %Schema{type: :integer, minimum: 0},
      current_event_head_hash: RefMDWeb.Schemas.Blake3Base64Url,
      redeem_authority_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      recipient_redeem_nonce: %Schema{type: :string},
      recipient_nonce_state_hash: RefMDWeb.Schemas.Blake3Base64Url,
      live_redeem_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url,
      redeem_freshness_proof_hash: RefMDWeb.Schemas.Blake3Base64Url,
      not_after_event_sequence: %Schema{type: :integer, minimum: 1}
    },
    required: [
      :protocol,
      :version,
      :authorization_id,
      :redeem_attempt_id,
      :workspace_id,
      :context_kind,
      :context_id,
      :resource_hash,
      :recipient,
      :workspace_pin_bootstrap_hash,
      :current_checkpoint_sequence,
      :current_checkpoint_hash,
      :current_event_head_sequence,
      :current_event_head_hash,
      :redeem_authority_signing_key_id,
      :recipient_redeem_nonce,
      :recipient_nonce_state_hash,
      :live_redeem_challenge_hash,
      :redeem_freshness_proof_hash,
      :not_after_event_sequence
    ]
  })
end

defmodule RefMDWeb.Schemas.RecipientBoundAuthorizationTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  actor = %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["device"]},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      key_scope_kind: %Schema{type: :string, enum: ["workspace"]},
      key_scope_id: %Schema{type: :string, format: :uuid},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :signer_kind,
      :user_id,
      :device_id,
      :signing_key_id,
      :key_scope_kind,
      :key_scope_id,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  }

  authority_boundary = %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      authorization_id: %Schema{type: :string, format: :uuid},
      redeem_attempt_id: %Schema{type: :string, format: :uuid},
      context_kind: %Schema{
        type: :string,
        enum: ["workspace_invitation", "guest_invitation"]
      },
      context_id: %Schema{type: :string, format: :uuid},
      current_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      current_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      current_event_head_sequence: %Schema{type: :integer, minimum: 0},
      current_event_head_hash: RefMDWeb.Schemas.Blake3Base64Url,
      resource_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspace_pin_bootstrap_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :workspace_id,
      :authorization_id,
      :redeem_attempt_id,
      :context_kind,
      :context_id,
      :current_checkpoint_sequence,
      :current_checkpoint_hash,
      :current_event_head_sequence,
      :current_event_head_hash,
      :resource_hash,
      :workspace_pin_bootstrap_hash
    ]
  }

  freshness = %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      recipient_redeem_nonce: %Schema{type: :string},
      recipient_nonce_state_hash: RefMDWeb.Schemas.Blake3Base64Url,
      live_redeem_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url,
      redeem_freshness_proof_hash: RefMDWeb.Schemas.Blake3Base64Url,
      not_after_event_sequence: %Schema{type: :integer, minimum: 1}
    },
    required: [
      :recipient_redeem_nonce,
      :recipient_nonce_state_hash,
      :live_redeem_challenge_hash,
      :redeem_freshness_proof_hash,
      :not_after_event_sequence
    ]
  }

  OpenApiSpex.schema(%{
    title: "RecipientBoundAuthorizationTranscript",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature-transcript"]},
      label: %Schema{type: :string, enum: ["RefMD hybrid signature transcript v1"]},
      version: %Schema{type: :integer, enum: [1]},
      transcript_owner: %Schema{type: :string},
      surface_id: %Schema{type: :string},
      surface_variant: %Schema{type: :string, enum: ["none"]},
      signing_purpose: %Schema{type: :string, enum: ["recipient_bound_authorization"]},
      owner_kind: %Schema{type: :string, enum: ["device"]},
      owner_id: %Schema{type: :string, format: :uuid},
      signature_suite_id: %Schema{
        type: :string,
        enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]
      },
      signature_suite_rank: %Schema{type: :integer, enum: [1000]},
      subject_hash: RefMDWeb.Schemas.Blake3Base64Url,
      subject_protocol: %Schema{type: :string, enum: ["refmd.recipient-bound-authorization"]},
      subject_version: %Schema{type: :integer, enum: [1]},
      actor: actor,
      authority_boundary: authority_boundary,
      recipient: RefMDWeb.Schemas.RecipientBoundAuthorizationRecipient,
      freshness: freshness
    },
    required: [
      :protocol,
      :label,
      :version,
      :transcript_owner,
      :surface_id,
      :surface_variant,
      :signing_purpose,
      :owner_kind,
      :owner_id,
      :signature_suite_id,
      :signature_suite_rank,
      :subject_hash,
      :subject_protocol,
      :subject_version,
      :actor,
      :authority_boundary,
      :recipient,
      :freshness
    ]
  })
end

defmodule RefMDWeb.Schemas.RecipientBoundAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecipientBoundAuthorization",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: RefMDWeb.Schemas.RecipientBoundAuthorizationPayload,
      transcript: RefMDWeb.Schemas.RecipientBoundAuthorizationTranscript,
      signature: RefMDWeb.Schemas.HybridSignature,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial
    },
    required: [
      :payload,
      :transcript,
      :signature,
      :signing_key_id,
      :hybrid_signing_public_key_material
    ]
  })
end

defmodule RefMDWeb.Schemas.MemberGossipPayload do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberGossipPayload",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.pin.gossip.statement"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      current_event_head_sequence: %Schema{type: :integer, minimum: 0},
      current_event_head_hash: RefMDWeb.Schemas.Blake3Base64Url,
      current_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      recipient_redeem_nonce: %Schema{type: :string},
      live_redeem_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required:
      ~w(protocol version workspace_id current_event_head_sequence current_event_head_hash current_checkpoint_hash user_id device_id recipient_redeem_nonce live_redeem_challenge_hash)a
  })
end

defmodule RefMDWeb.Schemas.PinGossipStatementTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PinGossipStatementTranscript",
    type: :object,
    additionalProperties: false,
    properties: %{
      label: %Schema{type: :string, enum: ["RefMD hybrid signature transcript v1"]},
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature-transcript"]},
      version: %Schema{type: :integer, enum: [1]},
      transcript_owner: %Schema{type: :string},
      surface_id: %Schema{type: :string, enum: ["pin_gossip_statement"]},
      surface_variant: %Schema{type: :string, enum: ["none"]},
      signing_purpose: %Schema{type: :string, enum: ["pin_gossip_statement"]},
      owner_kind: %Schema{type: :string, enum: ["device"]},
      owner_id: %Schema{type: :string, format: :uuid},
      signature_suite_id: %Schema{type: :string},
      signature_suite_rank: %Schema{type: :integer},
      subject_hash: RefMDWeb.Schemas.Blake3Base64Url,
      subject_protocol: %Schema{type: :string, enum: ["refmd.pin.gossip.statement"]},
      subject_version: %Schema{type: :integer, enum: [1]},
      pin_gossip: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          statement_hash: RefMDWeb.Schemas.Blake3Base64Url,
          statement: RefMDWeb.Schemas.MemberGossipPayload
        },
        required: [:statement_hash, :statement]
      }
    },
    required:
      ~w(label protocol version transcript_owner surface_id surface_variant signing_purpose owner_kind owner_id signature_suite_id signature_suite_rank subject_hash subject_protocol subject_version pin_gossip)a
  })
end

defmodule RefMDWeb.Schemas.MemberGossipStatement do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberGossipStatement",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: RefMDWeb.Schemas.MemberGossipPayload,
      transcript: RefMDWeb.Schemas.PinGossipStatementTranscript,
      signature: RefMDWeb.Schemas.HybridSignature,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial
    },
    required: [
      :payload,
      :transcript,
      :signature,
      :signing_key_id,
      :hybrid_signing_public_key_material
    ]
  })
end

defmodule RefMDWeb.Schemas.AuthoritativeDeviceLiveFreshnessProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AuthoritativeDeviceLiveFreshnessProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.redeem-freshness-proof"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      current_event_head_sequence: %Schema{type: :integer, minimum: 0},
      current_event_head_hash: RefMDWeb.Schemas.Blake3Base64Url,
      current_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      proof_kind: %Schema{type: :string, enum: ["authoritative_device_live"]},
      authoritative_device: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          user_id: %Schema{type: :string, format: :uuid},
          device_id: %Schema{type: :string, format: :uuid}
        },
        required: [:user_id, :device_id]
      },
      recipient_redeem_nonce: %Schema{type: :string},
      live_redeem_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :protocol,
      :version,
      :workspace_id,
      :current_event_head_sequence,
      :current_event_head_hash,
      :current_checkpoint_hash,
      :proof_kind,
      :authoritative_device,
      :recipient_redeem_nonce,
      :live_redeem_challenge_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.MemberGossipQuorumFreshnessProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberGossipQuorumFreshnessProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.redeem-freshness-proof"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      current_event_head_sequence: %Schema{type: :integer, minimum: 0},
      current_event_head_hash: RefMDWeb.Schemas.Blake3Base64Url,
      current_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      proof_kind: %Schema{type: :string, enum: ["member_gossip_quorum"]},
      proof_hashes: %Schema{type: :array, minItems: 2, items: RefMDWeb.Schemas.Blake3Base64Url},
      gossip_statements: %Schema{
        type: :array,
        minItems: 2,
        items: RefMDWeb.Schemas.MemberGossipStatement
      },
      recipient_redeem_nonce: %Schema{type: :string},
      live_redeem_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required:
      ~w(protocol version workspace_id current_event_head_sequence current_event_head_hash current_checkpoint_hash proof_kind proof_hashes gossip_statements recipient_redeem_nonce live_redeem_challenge_hash)a
  })
end

defmodule RefMDWeb.Schemas.RedeemFreshnessProof do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RedeemFreshnessProof",
    oneOf: [
      RefMDWeb.Schemas.AuthoritativeDeviceLiveFreshnessProof,
      RefMDWeb.Schemas.MemberGossipQuorumFreshnessProof
    ]
  })
end

defmodule RefMDWeb.Schemas.ApproveInvitationDeliveryAttemptRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ApproveInvitationDeliveryAttemptRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      authorization: RefMDWeb.Schemas.RecipientBoundAuthorization,
      redeem_freshness_proof: RefMDWeb.Schemas.RedeemFreshnessProof,
      workspace_pin_bootstrap: RefMDWeb.Schemas.WorkspacePinBootstrap,
      delivery_wrap: RefMDWeb.Schemas.HybridKeyWrapFields,
      member_envelope: %Schema{allOf: [RefMDWeb.Schemas.MemberEnvelopeItem], nullable: true},
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      workspace_key_directory_intermediate_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      }
    },
    required: [
      :authorization,
      :redeem_freshness_proof,
      :workspace_pin_bootstrap,
      :delivery_wrap,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.ConsumeInvitationDeliveryAttemptRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ConsumeInvitationDeliveryAttemptRequest",
    type: :object,
    additionalProperties: false,
    properties: %{token: %Schema{type: :string}},
    required: [:token]
  })
end
