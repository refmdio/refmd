defmodule RefMDWeb.Schemas.GenesisRecoveryAuthorizationPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "GenesisRecoveryAuthorizationPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signing-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["recovery_authorization"]},
      owner_id: %Schema{type: :string, format: :uuid},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      ed25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mldsa65_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 2603,
        maxLength: 2603
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :ed25519_public,
      :mldsa65_public
    ]
  })
end

defmodule RefMDWeb.Schemas.GenesisRecoveryAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GenesisRecoveryAuthorization",
    type: :object,
    additionalProperties: false,
    properties: %{
      recovery_encrypted_umk: %Schema{type: :string, minLength: 1},
      recovery_nonce: RefMDWeb.Schemas.EncryptedMaterialNonce,
      recovery_authorization_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      recovery_authorization_public_material:
        RefMDWeb.Schemas.GenesisRecoveryAuthorizationPublicKeyMaterial
    },
    required: [
      :recovery_encrypted_umk,
      :recovery_nonce,
      :recovery_authorization_key_id,
      :recovery_authorization_public_material
    ]
  })
end

defmodule RefMDWeb.Schemas.GenesisSuitePolicy do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GenesisSuitePolicy",
    type: :object,
    additionalProperties: false,
    properties: %{
      suite_policy_version: %Schema{type: :integer, minimum: 1},
      min_suite_rank: %Schema{type: :integer, minimum: 1},
      allowed_suite_ids: %Schema{
        type: :array,
        minItems: 1,
        items: %Schema{type: :string, minLength: 1}
      }
    },
    required: [:suite_policy_version, :min_suite_rank, :allowed_suite_ids]
  })
end

defmodule RefMDWeb.Schemas.GenesisWorkspaceMemberEnvelopePrecommit do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @key_scope_properties %{
    key_scope_kind: %Schema{type: :string, enum: ["workspace"]},
    key_scope_id: %Schema{type: :string, format: :uuid},
    key_checkpoint_sequence: %Schema{type: :integer, enum: [0]},
    key_checkpoint_hash: %Schema{type: :string, enum: ["GENESIS"]}
  }

  @sender %Schema{
    type: :object,
    additionalProperties: false,
    properties:
      Map.merge(@key_scope_properties, %{
        signer_kind: %Schema{type: :string, enum: ["device"]},
        user_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid},
        signing_key_id: RefMDWeb.Schemas.Blake3Base64Url
      }),
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

  @recipient %Schema{
    type: :object,
    additionalProperties: false,
    properties:
      Map.merge(@key_scope_properties, %{
        recipient_kind: %Schema{type: :string, enum: ["user_identity"]},
        user_id: %Schema{type: :string, format: :uuid},
        encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url
      }),
    required: [
      :recipient_kind,
      :user_id,
      :encryption_key_id,
      :key_scope_kind,
      :key_scope_id,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  }

  @wrap %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.signed-pq-hybrid-wrap"]},
      protocol_version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, minLength: 1},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      purpose: %Schema{type: :string, enum: ["workspace_member_kek_wrap"]},
      resource: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          workspace_id: %Schema{type: :string, format: :uuid},
          target_user_id: %Schema{type: :string, format: :uuid},
          kek_version: %Schema{type: :integer, enum: [1]}
        },
        required: [:workspace_id, :target_user_id, :kek_version]
      },
      sender: @sender,
      recipient: @recipient,
      event_scope: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          scope_kind: %Schema{type: :string, enum: ["workspace"]},
          scope_id: %Schema{type: :string, format: :uuid}
        },
        required: [:scope_kind, :scope_id]
      },
      hpke: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          mode: %Schema{type: :string, enum: ["base"]},
          kem_id: %Schema{type: :integer, enum: [25_722]},
          kdf_id: %Schema{type: :integer, enum: [1]},
          aead_id: %Schema{type: :integer, enum: [3]},
          enc: %Schema{type: :string, minLength: 1},
          ciphertext: %Schema{type: :string, minLength: 1}
        },
        required: [:mode, :kem_id, :kdf_id, :aead_id, :enc, :ciphertext]
      }
    },
    required: [
      :protocol,
      :protocol_version,
      :suite_id,
      :suite_rank,
      :purpose,
      :resource,
      :sender,
      :recipient,
      :event_scope,
      :hpke
    ]
  }

  OpenApiSpex.schema(%{
    title: "GenesisWorkspaceMemberEnvelopePrecommit",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.workspace-member-envelope"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      target_user_id: %Schema{type: :string, format: :uuid},
      kek_version: %Schema{type: :integer, enum: [1]},
      target_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      target_identity_key_material_hash: RefMDWeb.Schemas.Blake3Base64Url,
      authorization_key_directory_checkpoint_sequence: %Schema{type: :integer, enum: [1]},
      authorization_key_directory_checkpoint_hash: %Schema{type: :string, enum: ["GENESIS"]},
      wrap: @wrap
    },
    required: [
      :protocol,
      :version,
      :workspace_id,
      :target_user_id,
      :kek_version,
      :target_identity_encryption_key_id,
      :target_identity_key_material_hash,
      :authorization_key_directory_checkpoint_sequence,
      :authorization_key_directory_checkpoint_hash,
      :wrap
    ]
  })
end

defmodule RefMDWeb.Schemas.AccountGenesisPrepareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AccountGenesisPrepareRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      registration_id: %Schema{type: :string, format: :uuid},
      registration_challenge: %Schema{type: :string, minLength: 1},
      user_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      owner_role_id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string, minLength: 1},
      device_type: %Schema{type: :string, enum: ["browser", "desktop", "mobile"]},
      device_id: %Schema{type: :string, format: :uuid},
      encrypted_umk: %Schema{type: :string, minLength: 1},
      encrypted_umk_nonce: RefMDWeb.Schemas.EncryptedMaterialNonce,
      recoverable_identity_secret_record: RefMDWeb.Schemas.RecoverableIdentitySecretRecord,
      identity_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      identity_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial,
      identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      device_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      device_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      device_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
      device_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      recovery_authorization: RefMDWeb.Schemas.GenesisRecoveryAuthorization,
      initial_suite_policy: RefMDWeb.Schemas.GenesisSuitePolicy,
      workspace_member_envelope_precommit:
        RefMDWeb.Schemas.GenesisWorkspaceMemberEnvelopePrecommit,
      client_nonce: %Schema{type: :string, minLength: 1}
    },
    required: [
      :registration_id,
      :registration_challenge,
      :user_id,
      :workspace_id,
      :owner_role_id,
      :name,
      :device_type,
      :device_id,
      :encrypted_umk,
      :encrypted_umk_nonce,
      :recoverable_identity_secret_record,
      :identity_hybrid_signing_public_key_material,
      :identity_signing_key_id,
      :identity_hybrid_encryption_public_key_material,
      :identity_encryption_key_id,
      :device_hybrid_signing_public_key_material,
      :device_signing_key_id,
      :device_hybrid_encryption_public_key_material,
      :device_encryption_key_id,
      :recovery_authorization,
      :initial_suite_policy,
      :workspace_member_envelope_precommit,
      :client_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.GenesisScopeSignature do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GenesisScopeSignature",
    type: :object,
    additionalProperties: false,
    properties: %{
      chain_scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      chain_scope_id: %Schema{type: :string, format: :uuid},
      checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      checkpoint_variant: %Schema{
        type: :string,
        enum: ["user_identity", "user_device", "workspace_device", "workspace_guest_device"]
      },
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [
      :chain_scope_kind,
      :chain_scope_id,
      :checkpoint_hash,
      :checkpoint_variant,
      :signature
    ]
  })
end

defmodule RefMDWeb.Schemas.GenesisEffectAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GenesisEffectAuthorization",
    type: :object,
    additionalProperties: false,
    properties: %{
      requirement_order: %Schema{type: :integer, minimum: 1},
      authorization_kind: %Schema{
        type: :string,
        enum: [
          "key_directory_event",
          "key_directory_checkpoint",
          "pq_wrap",
          "genesis_device_bootstrap"
        ]
      },
      signing_purpose: %Schema{type: :string, minLength: 1},
      surface_variant: %Schema{type: :string, minLength: 1},
      subject_hash: RefMDWeb.Schemas.Blake3Base64Url,
      signer_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      signature: RefMDWeb.Schemas.HybridSignature,
      approval_proof: %Schema{type: :string, enum: ["NONE"]}
    },
    required: [
      :requirement_order,
      :authorization_kind,
      :signing_purpose,
      :surface_variant,
      :subject_hash,
      :signer_key_id,
      :signature,
      :approval_proof
    ]
  })
end

defmodule RefMDWeb.Schemas.BootstrapDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "BootstrapDeviceRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.audit.compound-append-authorization"]},
      version: %Schema{type: :integer, enum: [1]},
      compound_intent_id: %Schema{type: :string, format: :uuid},
      mutation_id: %Schema{type: :string, format: :uuid},
      intent_hash: RefMDWeb.Schemas.Blake3Base64Url,
      scope_signatures: %Schema{
        type: :array,
        minItems: 2,
        maxItems: 2,
        items: RefMDWeb.Schemas.GenesisScopeSignature
      },
      effect_authorizations: %Schema{
        type: :array,
        minItems: 1,
        items: RefMDWeb.Schemas.GenesisEffectAuthorization
      }
    },
    required: [
      :protocol,
      :version,
      :compound_intent_id,
      :mutation_id,
      :intent_hash,
      :scope_signatures,
      :effect_authorizations
    ]
  })
end

defmodule RefMDWeb.Schemas.BootstrapRegistrationChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "BootstrapRegistrationChallengeResponse",
    type: :object,
    properties: %{
      registration_challenge: %Schema{type: :string},
      expires_in_seconds: %Schema{type: :integer}
    },
    required: [:registration_challenge, :expires_in_seconds]
  })
end

defmodule RefMDWeb.Schemas.RegistrationChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegistrationChallengeResponse",
    type: :object,
    properties: %{
      registration_challenge: %Schema{type: :string},
      expires_in_seconds: %Schema{type: :integer},
      issued_at_ms: %Schema{type: :integer, minimum: 0},
      expires_at_ms: %Schema{type: :integer, minimum: 0}
    },
    required: [:registration_challenge, :expires_in_seconds, :issued_at_ms, :expires_at_ms]
  })
end

defmodule RefMDWeb.Schemas.BootstrapDeviceResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "BootstrapDeviceResponse",
    type: :object,
    properties: %{
      status: %Schema{type: :string, enum: ["committed"]},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      user_audit_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspace_audit_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :status,
      :user_id,
      :device_id,
      :workspace_id,
      :user_audit_checkpoint_hash,
      :workspace_audit_checkpoint_hash
    ]
  })
end
