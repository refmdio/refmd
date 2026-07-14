defmodule RefMDWeb.Schemas.InitialAkeArtifact do
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeArtifact",
      oneOf: [
        RefMDWeb.Schemas.InitialAkeUmkArtifact,
        RefMDWeb.Schemas.InitialAkeApprovalArtifact,
        RefMDWeb.Schemas.InitialAkeTrustTransferArtifact
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeOffer do
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    title: "InitialAkeOffer",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
      version: %Schema{type: :integer, enum: [1]},
      ake_suite_id: %Schema{type: :string},
      ake_suite_rank: %Schema{type: :integer},
      purpose: %Schema{type: :string},
      transcript: %Schema{
        oneOf: [
          RefMDWeb.Schemas.InitialAkeUmkTranscript,
          RefMDWeb.Schemas.InitialAkeApprovalTranscript,
          RefMDWeb.Schemas.InitialAkeTrustTransferTranscript
        ]
      },
      transcript_hash: %Schema{type: :string},
      initiator_commitment: %Schema{
        allOf: [RefMDWeb.Schemas.InitiatorAkeCommitment]
      },
      initiator_commitment_signature: RefMDWeb.Schemas.HybridSignature,
      initiator_confirmation: %Schema{type: :string},
      pending_delivery: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          metadata: %Schema{allOf: [RefMDWeb.Schemas.InitialAkePendingDeliveryMetadata]},
          aead: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAead]}
        },
        required: [:metadata, :aead]
      }
    },
    required: [
      :protocol,
      :version,
      :ake_suite_id,
      :ake_suite_rank,
      :purpose,
      :transcript,
      :transcript_hash,
      :initiator_commitment,
      :initiator_commitment_signature,
      :initiator_confirmation,
      :pending_delivery
    ],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeResponderConfirmation do
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    title: "InitialAkeResponderConfirmation",
    type: :object,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.initial-ake-responder-confirmation"]},
      version: %Schema{type: :integer, enum: [1]},
      purpose: %Schema{type: :string},
      transcript_hash: %Schema{type: :string},
      prekey_id: %Schema{type: :string},
      responder_confirmation: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :purpose,
      :transcript_hash,
      :prekey_id,
      :responder_confirmation
    ],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeOfferBundle do
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    title: "InitialAkeOfferBundle",
    type: :object,
    properties: %{
      umk_distribution: RefMDWeb.Schemas.InitialAkeOffer,
      trust_transfer: RefMDWeb.Schemas.InitialAkeOffer,
      device_approval_kek_initial: %Schema{
        type: :object,
        additionalProperties: RefMDWeb.Schemas.InitialAkeOffer
      }
    },
    required: [:umk_distribution, :trust_transfer, :device_approval_kek_initial],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeResponseBundle do
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    title: "InitialAkeResponseBundle",
    type: :object,
    properties: %{
      umk_distribution: RefMDWeb.Schemas.InitialAkeResponderConfirmation,
      trust_transfer: RefMDWeb.Schemas.InitialAkeResponderConfirmation,
      device_approval_kek_initial: %Schema{
        type: :object,
        additionalProperties: RefMDWeb.Schemas.InitialAkeResponderConfirmation
      }
    },
    required: [:umk_distribution, :trust_transfer, :device_approval_kek_initial],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeExchangeResponse do
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    title: "InitialAkeExchangeResponse",
    type: :object,
    properties: %{
      offers: RefMDWeb.Schemas.InitialAkeOfferBundle,
      sender_device_id: %Schema{type: :string},
      sender_hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial
    },
    required: [:offers, :sender_device_id, :sender_hybrid_signing_public_key_material],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeResponsesRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InitialAkeResponsesRequest",
    type: :object,
    properties: %{responses: RefMDWeb.Schemas.InitialAkeResponseBundle},
    required: [:responses],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeResponsesResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InitialAkeResponsesResponse",
    type: :object,
    properties: %{responses: RefMDWeb.Schemas.InitialAkeResponseBundle},
    required: [:responses],
    struct?: false
  })
end

defmodule RefMDWeb.Schemas.InitialAkeRequiredComponents do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @required_components [
    "x25519-ephemeral",
    "mlkem768-ephemeral",
    "hkdf-sha256",
    "initiator-ake-commitment",
    "responder-prekey-signature"
  ]

  OpenApiSpex.schema(
    %{
      title: "InitialAkeRequiredComponents",
      type: :array,
      minItems: length(@required_components),
      maxItems: length(@required_components),
      items: %Schema{type: :string, enum: @required_components}
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeUmkArtifact do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialAkeUmkArtifact",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        purpose: %Schema{type: :string, enum: ["umk_distribution"]},
        transcript: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeUmkTranscript]},
        transcript_hash: %Schema{type: :string},
        initiator_commitment: %Schema{allOf: [RefMDWeb.Schemas.InitiatorAkeCommitment]},
        initiator_commitment_signature: RefMDWeb.Schemas.HybridSignature,
        initiator_confirmation: %Schema{type: :string},
        responder_confirmation: %Schema{type: :string}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :purpose,
        :transcript,
        :transcript_hash,
        :initiator_commitment,
        :initiator_commitment_signature,
        :initiator_confirmation,
        :responder_confirmation
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeApprovalArtifact do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialAkeApprovalArtifact",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        purpose: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
        transcript: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeApprovalTranscript]},
        transcript_hash: %Schema{type: :string},
        initiator_commitment: %Schema{allOf: [RefMDWeb.Schemas.InitiatorAkeCommitment]},
        initiator_commitment_signature: RefMDWeb.Schemas.HybridSignature,
        initiator_confirmation: %Schema{type: :string},
        responder_confirmation: %Schema{type: :string}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :purpose,
        :transcript,
        :transcript_hash,
        :initiator_commitment,
        :initiator_commitment_signature,
        :initiator_confirmation,
        :responder_confirmation
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTrustTransferArtifact do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTrustTransferArtifact",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        purpose: %Schema{type: :string, enum: ["trust_transfer"]},
        transcript: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTrustTransferTranscript]},
        transcript_hash: %Schema{type: :string},
        initiator_commitment: %Schema{allOf: [RefMDWeb.Schemas.InitiatorAkeCommitment]},
        initiator_commitment_signature: RefMDWeb.Schemas.HybridSignature,
        initiator_confirmation: %Schema{type: :string},
        responder_confirmation: %Schema{type: :string}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :purpose,
        :transcript,
        :transcript_hash,
        :initiator_commitment,
        :initiator_commitment_signature,
        :initiator_confirmation,
        :responder_confirmation
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTranscript do
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTranscript",
      oneOf: [
        RefMDWeb.Schemas.InitialAkeUmkTranscript,
        RefMDWeb.Schemas.InitialAkeApprovalTranscript,
        RefMDWeb.Schemas.InitialAkeTrustTransferTranscript
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeUmkTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialAkeUmkTranscript",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        required_components: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeRequiredComponents]},
        purpose: %Schema{type: :string, enum: ["umk_distribution"]},
        initiator: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTranscriptInitiator]},
        responder: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTranscriptResponder]},
        context: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeUmkContext]},
        directory: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeUmkDirectory]}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :required_components,
        :purpose,
        :initiator,
        :responder,
        :context,
        :directory
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeApprovalTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialAkeApprovalTranscript",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        required_components: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeRequiredComponents]},
        purpose: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
        initiator: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTranscriptInitiator]},
        responder: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTranscriptResponder]},
        context: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeApprovalContext]},
        directory: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeApprovalDirectory]}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :required_components,
        :purpose,
        :initiator,
        :responder,
        :context,
        :directory
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTrustTransferTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTrustTransferTranscript",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-hybrid-key-agreement"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        required_components: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeRequiredComponents]},
        purpose: %Schema{type: :string, enum: ["trust_transfer"]},
        initiator: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTranscriptInitiator]},
        responder: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTranscriptResponder]},
        context: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTrustTransferContext]},
        directory: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeTrustTransferDirectory]}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :required_components,
        :purpose,
        :initiator,
        :responder,
        :context,
        :directory
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTranscriptInitiator do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTranscriptInitiator",
      type: :object,
      additionalProperties: false,
      properties: %{
        user_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid},
        signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
        x25519_ephemeral_public: %Schema{type: :string},
        mlkem768_enc: %Schema{type: :string},
        initiator_commitment_hash: %Schema{type: :string}
      },
      required: [
        :user_id,
        :device_id,
        :signing_key_id,
        :x25519_ephemeral_public,
        :mlkem768_enc,
        :initiator_commitment_hash
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTranscriptResponder do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTranscriptResponder",
      type: :object,
      additionalProperties: false,
      properties: %{
        signer_kind: %Schema{type: :string, enum: ["device"]},
        user_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid},
        signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
        x25519_ephemeral_public: %Schema{type: :string},
        mlkem768_ephemeral_public_hash: %Schema{type: :string},
        prekey_id: %Schema{type: :string, format: :uuid},
        prekey_hash: %Schema{type: :string}
      },
      required: [
        :signer_kind,
        :user_id,
        :device_id,
        :signing_key_id,
        :x25519_ephemeral_public,
        :mlkem768_ephemeral_public_hash,
        :prekey_id,
        :prekey_hash
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeUmkContext do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeUmkContext",
      type: :object,
      additionalProperties: false,
      properties: %{
        purpose: %Schema{type: :string, enum: ["umk_distribution"]},
        owner_user_id: %Schema{type: :string, format: :uuid},
        distribution_id: %Schema{type: :string},
        recipient_device_id: %Schema{type: :string, format: :uuid},
        target_key_kind: %Schema{type: :string},
        target_key_version: %Schema{type: :integer},
        operation_id: %Schema{type: :string},
        challenge: %Schema{type: :string}
      },
      required: [
        :purpose,
        :owner_user_id,
        :distribution_id,
        :recipient_device_id,
        :target_key_kind,
        :target_key_version,
        :operation_id,
        :challenge
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeApprovalContext do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeApprovalContext",
      type: :object,
      additionalProperties: false,
      properties: %{
        purpose: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
        owner_user_id: %Schema{type: :string, format: :uuid},
        workspace_id: %Schema{type: :string, format: :uuid},
        registration_id: %Schema{type: :string, format: :uuid},
        approved_device_id: %Schema{type: :string, format: :uuid},
        target_key_kind: %Schema{type: :string},
        target_key_version: %Schema{type: :integer},
        operation_id: %Schema{type: :string},
        challenge: %Schema{type: :string}
      },
      required: [
        :purpose,
        :owner_user_id,
        :workspace_id,
        :registration_id,
        :approved_device_id,
        :target_key_kind,
        :target_key_version,
        :operation_id,
        :challenge
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTrustTransferContext do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTrustTransferContext",
      type: :object,
      additionalProperties: false,
      properties: %{
        purpose: %Schema{type: :string, enum: ["trust_transfer"]},
        owner_user_id: %Schema{type: :string, format: :uuid},
        trust_transfer_id: %Schema{type: :string},
        source_device_id: %Schema{type: :string, format: :uuid},
        target_device_id: %Schema{type: :string, format: :uuid},
        transfer_scope_hash: %Schema{type: :string},
        target_payload_kind: %Schema{type: :string, enum: ["trust_state_bundle"]},
        operation_id: %Schema{type: :string},
        challenge: %Schema{type: :string}
      },
      required: [
        :purpose,
        :owner_user_id,
        :trust_transfer_id,
        :source_device_id,
        :target_device_id,
        :transfer_scope_hash,
        :target_payload_kind,
        :operation_id,
        :challenge
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeUmkDirectory do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeUmkDirectory",
      type: :object,
      additionalProperties: false,
      properties: %{
        user_checkpoint_hash: %Schema{type: :string},
        user_event_head_hash: %Schema{type: :string},
        suite_policy_version: %Schema{type: :integer},
        min_suite_rank: %Schema{type: :integer},
        allowed_suite_ids_hash: %Schema{type: :string}
      },
      required: [
        :user_checkpoint_hash,
        :user_event_head_hash,
        :suite_policy_version,
        :min_suite_rank,
        :allowed_suite_ids_hash
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeApprovalDirectory do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeApprovalDirectory",
      type: :object,
      additionalProperties: false,
      properties: %{
        user_checkpoint_hash: %Schema{type: :string},
        workspace_checkpoint_hash: %Schema{type: :string},
        event_head_hash: %Schema{type: :string},
        suite_policy_version: %Schema{type: :integer},
        min_suite_rank: %Schema{type: :integer},
        allowed_suite_ids_hash: %Schema{type: :string}
      },
      required: [
        :user_checkpoint_hash,
        :workspace_checkpoint_hash,
        :event_head_hash,
        :suite_policy_version,
        :min_suite_rank,
        :allowed_suite_ids_hash
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeTrustTransferDirectory do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeTrustTransferDirectory",
      type: :object,
      additionalProperties: false,
      properties: %{
        user_checkpoint_hash: %Schema{type: :string},
        user_event_head_hash: %Schema{type: :string},
        workspace_pins_hash: %Schema{type: :string},
        suite_policy_version: %Schema{type: :integer},
        min_suite_rank: %Schema{type: :integer},
        allowed_suite_ids_hash: %Schema{type: :string}
      },
      required: [
        :user_checkpoint_hash,
        :user_event_head_hash,
        :workspace_pins_hash,
        :suite_policy_version,
        :min_suite_rank,
        :allowed_suite_ids_hash
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitiatorAkeCommitment do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_ake_suite_id "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitiatorAkeCommitment",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initiator-ake-commitment"]},
        version: %Schema{type: :integer, enum: [1]},
        ake_suite_id: %Schema{type: :string, enum: [@initial_ake_suite_id]},
        ake_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        initial_delivery_suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
        initial_delivery_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        purpose: %Schema{
          type: :string,
          enum: ["umk_distribution", "device_approval_kek_initial", "trust_transfer"]
        },
        operation_id: %Schema{type: :string},
        initiator: %Schema{allOf: [RefMDWeb.Schemas.InitiatorAkeCommitmentInitiator]},
        ake_inputs: %Schema{allOf: [RefMDWeb.Schemas.InitiatorAkeCommitmentInputs]},
        context_hash: %Schema{type: :string},
        directory_hash: %Schema{type: :string},
        recipient_hash: %Schema{type: :string},
        server_challenge: %Schema{type: :string}
      },
      required: [
        :protocol,
        :version,
        :ake_suite_id,
        :ake_suite_rank,
        :initial_delivery_suite_id,
        :initial_delivery_suite_rank,
        :purpose,
        :operation_id,
        :initiator,
        :ake_inputs,
        :context_hash,
        :directory_hash,
        :recipient_hash,
        :server_challenge
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitiatorAkeCommitmentInitiator do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitiatorAkeCommitmentInitiator",
      type: :object,
      additionalProperties: false,
      properties: %{
        signer_kind: %Schema{type: :string, enum: ["active_device"]},
        user_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid},
        signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
        encryption_key_id: %Schema{type: :string},
        pending_registration_binding_hash: %Schema{type: :string}
      },
      required: [
        :signer_kind,
        :user_id,
        :device_id,
        :signing_key_id,
        :encryption_key_id,
        :pending_registration_binding_hash
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitiatorAkeCommitmentInputs do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitiatorAkeCommitmentInputs",
      type: :object,
      additionalProperties: false,
      properties: %{
        x25519_ephemeral_public: %Schema{type: :string},
        mlkem768_enc: %Schema{type: :string},
        responder_prekey_hash: %Schema{type: :string}
      },
      required: [:x25519_ephemeral_public, :mlkem768_enc, :responder_prekey_hash]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryRecord do
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryRecord",
      oneOf: [
        RefMDWeb.Schemas.InitialKeyDeliveryUmkRecord,
        RefMDWeb.Schemas.InitialKeyDeliveryApprovalRecord,
        RefMDWeb.Schemas.InitialKeyDeliveryTrustTransferRecord
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryUmkRecord do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryUmkRecord",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-key-delivery"]},
        version: %Schema{type: :integer, enum: [1]},
        purpose: %Schema{type: :string, enum: ["umk_distribution"]},
        variant: %Schema{type: :string, enum: ["umk_distribution"]},
        initial_delivery_suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
        initial_delivery_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        metadata: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryMetadata]},
        aead: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAead]},
        authority: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAuthority]},
        signature: RefMDWeb.Schemas.HybridSignature
      },
      required: [
        :protocol,
        :version,
        :purpose,
        :variant,
        :initial_delivery_suite_id,
        :initial_delivery_suite_rank,
        :metadata,
        :aead,
        :authority,
        :signature
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryApprovalRecord do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryApprovalRecord",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-key-delivery"]},
        version: %Schema{type: :integer, enum: [1]},
        purpose: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
        variant: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
        initial_delivery_suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
        initial_delivery_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        metadata: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryApprovalMetadata]},
        aead: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAead]},
        authority: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAuthority]},
        signature: RefMDWeb.Schemas.HybridSignature
      },
      required: [
        :protocol,
        :version,
        :purpose,
        :variant,
        :initial_delivery_suite_id,
        :initial_delivery_suite_rank,
        :metadata,
        :aead,
        :authority,
        :signature
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryTrustTransferRecord do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryTrustTransferRecord",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.initial-key-delivery"]},
        version: %Schema{type: :integer, enum: [1]},
        purpose: %Schema{type: :string, enum: ["trust_transfer"]},
        variant: %Schema{type: :string, enum: ["trust_transfer"]},
        initial_delivery_suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
        initial_delivery_suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        metadata: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryTrustTransferMetadata]},
        aead: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAead]},
        authority: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryAuthority]},
        signature: RefMDWeb.Schemas.HybridSignature
      },
      required: [
        :protocol,
        :version,
        :purpose,
        :variant,
        :initial_delivery_suite_id,
        :initial_delivery_suite_rank,
        :metadata,
        :aead,
        :authority,
        :signature
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryMetadata do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000
  @common %{
    delivery_id: %Schema{type: :string, format: :uuid},
    sender_device_id: %Schema{type: :string, format: :uuid},
    recipient_device_id: %Schema{type: :string, format: :uuid},
    recipient_encryption_key_id: %Schema{type: :string},
    ake_transcript_hash: %Schema{type: :string},
    context_hash: %Schema{type: :string},
    initiator_commitment_hash: %Schema{type: :string},
    recipient_challenge_hash: %Schema{type: :string},
    key_confirmation_hash: %Schema{type: :string},
    signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
    key_checkpoint_hash: %Schema{type: :string},
    key_version: %Schema{type: :integer},
    payload_kind: %Schema{type: :string},
    key_kind: %Schema{type: :string},
    resource_hash: %Schema{type: :string},
    suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
    suite_rank: %Schema{type: :integer, enum: [@suite_rank]}
  }
  @common_required Map.keys(@common)

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryMetadata",
      type: :object,
      additionalProperties: false,
      properties: @common,
      required: @common_required
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkePendingDeliveryMetadata do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @properties RefMDWeb.Schemas.InitialKeyDeliveryMetadata.schema().properties
              |> Map.delete(:key_confirmation_hash)
              |> Map.merge(%{
                workspace_id: %Schema{type: :string, format: :uuid},
                document_rollback_pin_set_hash: %Schema{type: :string}
              })
  @required RefMDWeb.Schemas.InitialKeyDeliveryMetadata.schema().required --
              [:key_confirmation_hash]

  OpenApiSpex.schema(
    %{
      title: "InitialAkePendingDeliveryMetadata",
      type: :object,
      additionalProperties: false,
      properties: @properties,
      required: @required
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryApprovalMetadata do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000
  @common RefMDWeb.Schemas.InitialKeyDeliveryMetadata.schema().properties

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryApprovalMetadata",
      type: :object,
      additionalProperties: false,
      properties:
        Map.merge(@common, %{
          suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
          suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
          workspace_id: %Schema{type: :string, format: :uuid}
        }),
      required: Map.keys(@common) ++ [:workspace_id]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryTrustTransferMetadata do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000
  @common RefMDWeb.Schemas.InitialKeyDeliveryMetadata.schema().properties

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryTrustTransferMetadata",
      type: :object,
      additionalProperties: false,
      properties:
        Map.merge(@common, %{
          suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
          suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
          document_rollback_pin_set_hash: %Schema{type: :string}
        }),
      required: Map.keys(@common) ++ [:document_rollback_pin_set_hash]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryAead do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @initial_delivery_suite_id "refmd-v2-initial-delivery-xchacha20poly1305"
  @suite_rank 1000

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryAead",
      type: :object,
      additionalProperties: false,
      properties: %{
        suite_id: %Schema{type: :string, enum: [@initial_delivery_suite_id]},
        suite_rank: %Schema{type: :integer, enum: [@suite_rank]},
        nonce: %Schema{type: :string},
        ciphertext: %Schema{type: :string},
        ciphertext_hash: %Schema{type: :string}
      },
      required: [:suite_id, :suite_rank, :nonce, :ciphertext, :ciphertext_hash]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryAuthority do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialKeyDeliveryAuthority",
      type: :object,
      additionalProperties: false,
      properties: %{
        sender_authority_kind: %Schema{type: :string, enum: ["device"]}
      },
      required: [:sender_authority_kind]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.InitialAkeDeliveryPair do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "InitialAkeDeliveryPair",
      type: :object,
      additionalProperties: false,
      properties: %{
        initial_ake: %Schema{allOf: [RefMDWeb.Schemas.InitialAkeArtifact]},
        initial_key_delivery: %Schema{allOf: [RefMDWeb.Schemas.InitialKeyDeliveryRecord]}
      },
      required: [:initial_ake, :initial_key_delivery]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.DistributeUmkRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "DistributeUmkRequest",
      type: :object,
      additionalProperties: false,
      properties: %{
        sender_device_id: %Schema{type: :string, format: :uuid},
        initial_ake: RefMDWeb.Schemas.InitialAkeArtifact,
        initial_key_delivery: RefMDWeb.Schemas.InitialKeyDeliveryRecord,
        initial_kek_deliveries: %Schema{
          type: :object,
          additionalProperties: RefMDWeb.Schemas.InitialAkeDeliveryPair
        },
        device_state_delivery: RefMDWeb.Schemas.InitialAkeDeliveryPair
      },
      required: [
        :sender_device_id,
        :initial_ake,
        :initial_key_delivery,
        :initial_kek_deliveries,
        :device_state_delivery
      ]
    },
    struct?: false
  )
end

defmodule RefMDWeb.Schemas.GetUmkResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(
    %{
      title: "GetUmkResponse",
      type: :object,
      properties: %{
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
        initial_ake: RefMDWeb.Schemas.InitialAkeArtifact,
        initial_key_delivery: RefMDWeb.Schemas.InitialKeyDeliveryRecord,
        initial_kek_deliveries: %Schema{
          type: :object,
          additionalProperties: RefMDWeb.Schemas.InitialAkeDeliveryPair
        },
        device_state_delivery: RefMDWeb.Schemas.InitialAkeDeliveryPair
      },
      required: [
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
        :initial_ake,
        :initial_key_delivery,
        :initial_kek_deliveries,
        :device_state_delivery
      ]
    },
    struct?: false
  )
end
