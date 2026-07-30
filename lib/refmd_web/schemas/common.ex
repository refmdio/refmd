defmodule RefMDWeb.Schemas.KdfParams do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KdfParams",
    type: :object,
    properties: %{
      algorithm: %Schema{type: :string},
      memory: %Schema{type: :integer},
      iterations: %Schema{type: :integer},
      parallelism: %Schema{type: :integer},
      hash_length: %Schema{type: :integer}
    },
    required: [:algorithm, :memory, :iterations, :parallelism, :hash_length]
  })
end

defmodule RefMDWeb.Schemas.UserInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UserInfo",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      email: %Schema{type: :string, format: :email},
      name: %Schema{type: :string}
    },
    required: [:id, :email, :name]
  })
end

defmodule RefMDWeb.Schemas.AuditCheckpointPayload do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash %Schema{type: :string, pattern: "^[A-Za-z0-9_-]{43}$", minLength: 43, maxLength: 43}

  OpenApiSpex.schema(%{
    title: "AuditCheckpointPayload",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.signed-audit-checkpoint"]},
      version: %Schema{type: :integer, enum: [1]},
      chain_scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      chain_scope_id: %Schema{type: :string, format: :uuid},
      sequence: %Schema{type: :integer, minimum: 1},
      event_hash: @hash,
      previous_signed_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      previous_signed_checkpoint_hash: @hash,
      signer_user_id: %Schema{type: :string, format: :uuid},
      signer_device_id: %Schema{type: :string, format: :uuid},
      signing_key_id: @hash,
      authorization_checkpoint_scope_kind: %Schema{
        type: :string,
        enum: ["user", "workspace"]
      },
      authorization_checkpoint_scope_id: %Schema{type: :string, format: :uuid},
      authorization_checkpoint_sequence: %Schema{type: :integer, minimum: 0},
      authorization_checkpoint_hash: %Schema{type: :string},
      covered_event_class: %Schema{type: :string, enum: ["authority"]},
      covered_event_type: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :chain_scope_kind,
      :chain_scope_id,
      :sequence,
      :event_hash,
      :signer_user_id,
      :signing_key_id,
      :authorization_checkpoint_scope_kind,
      :authorization_checkpoint_scope_id,
      :authorization_checkpoint_sequence,
      :authorization_checkpoint_hash,
      :covered_event_class,
      :covered_event_type
    ]
  })
end

defmodule RefMDWeb.Schemas.SignedAuditCheckpoint do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash %Schema{type: :string, pattern: "^[A-Za-z0-9_-]{43}$", minLength: 43, maxLength: 43}

  OpenApiSpex.schema(%{
    title: "SignedAuditCheckpoint",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: RefMDWeb.Schemas.AuditCheckpointPayload,
      signature: RefMDWeb.Schemas.HybridSignature,
      checkpoint_hash: @hash
    },
    required: [:payload, :signature, :checkpoint_hash]
  })
end

defmodule RefMDWeb.Schemas.AuditEventEnvelope do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash %Schema{type: :string, pattern: "^[A-Za-z0-9_-]{43}$", minLength: 43, maxLength: 43}
  @predecessor %Schema{type: :string, pattern: "^(GENESIS|[A-Za-z0-9_-]{43})$"}

  OpenApiSpex.schema(%{
    title: "AuditEventEnvelope",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.audit.chain-event"]},
      version: %Schema{type: :integer, enum: [1]},
      event_id: %Schema{type: :string, format: :uuid},
      chain_scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      chain_scope_id: %Schema{type: :string, format: :uuid},
      sequence: %Schema{type: :integer, minimum: 1},
      previous_event_hash: @predecessor,
      event_hash: @hash,
      event_type: %Schema{type: :string, minLength: 1},
      event_body: %Schema{type: :object}
    },
    required: [
      :protocol,
      :version,
      :event_id,
      :chain_scope_kind,
      :chain_scope_id,
      :sequence,
      :previous_event_hash,
      :event_hash,
      :event_type,
      :event_body
    ]
  })
end

defmodule RefMDWeb.Schemas.AuditEventHead do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash %Schema{type: :string, pattern: "^[A-Za-z0-9_-]{43}$", minLength: 43, maxLength: 43}

  OpenApiSpex.schema(%{
    title: "AuditEventHead",
    type: :object,
    additionalProperties: false,
    properties: %{
      sequence: %Schema{type: :integer, minimum: 1},
      event_hash: @hash
    },
    required: [:sequence, :event_hash]
  })
end

defmodule RefMDWeb.Schemas.AuditCheckpoint do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AuditCheckpoint",
    type: :object,
    additionalProperties: false,
    properties: %{
      signed_checkpoint: RefMDWeb.Schemas.SignedAuditCheckpoint,
      ancestry: %Schema{type: :array, items: RefMDWeb.Schemas.AuditEventEnvelope},
      current_event_head: RefMDWeb.Schemas.AuditEventHead,
      unsigned_tail: %Schema{type: :array, items: RefMDWeb.Schemas.AuditEventEnvelope}
    },
    required: [:signed_checkpoint, :ancestry, :current_event_head, :unsigned_tail]
  })
end

defmodule RefMDWeb.Schemas.UserInfoWithSetup do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UserInfoWithSetup",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      email: %Schema{type: :string, format: :email},
      name: %Schema{type: :string},
      encryption_setup_at: %Schema{type: :string, format: :"date-time", nullable: true}
    },
    required: [:id, :email, :name]
  })
end

defmodule RefMDWeb.Schemas.OkResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OkResponse",
    type: :object,
    properties: %{
      ok: %Schema{type: :boolean}
    },
    required: [:ok]
  })
end

defmodule RefMDWeb.Schemas.ErrorResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ErrorResponse",
    type: :object,
    properties: %{
      error: %Schema{type: :string},
      details: %Schema{
        oneOf: [
          %Schema{
            type: :array,
            items: RefMDWeb.Schemas.ErrorDetail
          },
          RefMDWeb.Schemas.ErrorContextDetails
        ]
      }
    },
    required: [:error]
  })
end

defmodule RefMDWeb.Schemas.ErrorDetail do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ErrorDetail",
    type: :object,
    additionalProperties: false,
    properties: %{
      reason: %Schema{type: :string},
      path: %Schema{type: :array, items: %Schema{type: :string}}
    },
    required: [:reason, :path]
  })
end

defmodule RefMDWeb.Schemas.ErrorContextDetails do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ErrorContextDetails",
    type: :object,
    additionalProperties: false,
    properties: %{
      current_kek_version: %Schema{type: :integer, nullable: true}
    }
  })
end

defmodule RefMDWeb.Schemas.Blake3Base64Url do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "Blake3Base64Url",
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  })
end

defmodule RefMDWeb.Schemas.KeyDirectoryEnvelope do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  }
  @extension_context_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      bootstrap_version: %Schema{type: :integer, minimum: 1},
      created_event_hash: @hash_schema,
      dek_version: %Schema{type: :integer, minimum: 1},
      device_id: %Schema{type: :string},
      document_scope_hash: @hash_schema,
      encryption_key_id: @hash_schema,
      guest_device_id: %Schema{type: :string},
      guest_grant_id: %Schema{type: :string},
      guest_invitation_id: %Schema{type: :string},
      guest_invitation_redeemed_event_hash: @hash_schema,
      guest_user_id: %Schema{type: :string},
      invitation_id: %Schema{type: :string},
      invitee_binding: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          kind: %Schema{type: :string, enum: ["email"]},
          email_hash: @hash_schema
        },
        required: [:kind, :email_hash]
      },
      invitee_device_id: %Schema{type: :string},
      invitee_user_id: %Schema{type: :string},
      key_checkpoint_hash: @hash_schema,
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_id: @hash_schema,
      key_material_hash: @hash_schema,
      key_scope_id: %Schema{type: :string},
      key_scope_kind: %Schema{type: :string},
      kek_version: %Schema{type: :integer, minimum: 1},
      owner_id: %Schema{type: :string},
      owner_kind: %Schema{type: :string},
      password_capability_secret_commitment: %Schema{
        oneOf: [@hash_schema, %Schema{type: :string, enum: ["none"]}]
      },
      password_protected: %Schema{type: :boolean},
      permission: %Schema{type: :string},
      principal_id: %Schema{type: :string},
      recipient_account_device_id: %Schema{type: :string},
      recipient_account_user_id: %Schema{type: :string},
      recipient_kind: %Schema{type: :string},
      recipient_device_id: %Schema{type: :string},
      recipient_encryption_key_id: @hash_schema,
      recipient_user_id: %Schema{type: :string},
      redeemed_device_id: %Schema{type: :string},
      redeemed_user_id: %Schema{type: :string},
      role_id: %Schema{type: :string},
      scope_id: %Schema{type: :string},
      scope_kind: %Schema{type: :string},
      share_capability_secret_commitment: @hash_schema,
      share_id: %Schema{type: :string},
      share_key_version: %Schema{type: :integer, minimum: 1},
      share_participant_device_id: %Schema{type: :string},
      share_participant_principal_id: %Schema{type: :string},
      share_session_id: %Schema{type: :string},
      signer_kind: %Schema{type: :string},
      signing_key_id: @hash_schema,
      target_device_id: %Schema{type: :string},
      target_user_id: %Schema{type: :string},
      token_hash: @hash_schema,
      user_id: %Schema{type: :string},
      workspace_id: %Schema{type: :string},
      workspace_invitation_redeemed_event_hash: @hash_schema,
      workspace_pin_bootstrap_hash: @hash_schema
    }
  }
  @key_version_context_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      dek_version: %Schema{oneOf: [%Schema{type: :integer, minimum: 1}, %Schema{type: :string}]},
      share_key_version: %Schema{
        oneOf: [%Schema{type: :integer, minimum: 1}, %Schema{type: :string}]
      },
      workspace_kek_version: %Schema{
        oneOf: [%Schema{type: :integer, minimum: 1}, %Schema{type: :string}]
      }
    }
  }
  @extension_object_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      actor_hash: @hash_schema,
      added_at_event_sequence: %Schema{type: :integer, minimum: 1},
      added_scope_hashes: %Schema{type: :array, items: @hash_schema},
      admission_nonce: %Schema{type: :string},
      allowed_share_ids_hash: @hash_schema,
      authorization_public_key_material: RefMDWeb.Schemas.ShareCapabilitySigningPublicKeyMaterial,
      authorization_public_key_material_hash: @hash_schema,
      authority_kind: %Schema{type: :string},
      authority_scope_id: %Schema{type: :string},
      base_role: %Schema{type: :string},
      bootstrap_key_commitment: @hash_schema,
      bootstrap_package_hash: @hash_schema,
      bootstrap_suite_id: %Schema{type: :string},
      capability_context_hash: @hash_schema,
      changed_at_event_sequence: %Schema{type: :integer, minimum: 1},
      checkpoint_hash: @hash_schema,
      checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      completed_at_event_sequence: %Schema{type: :integer, minimum: 1},
      completion_manifest_hash: @hash_schema,
      deleted_at_event_sequence: %Schema{type: :integer, minimum: 1},
      deletion_manifest_hash: @hash_schema,
      dek_version: %Schema{type: :integer, minimum: 1},
      device_id: %Schema{type: :string},
      document_id: %Schema{type: :string},
      document_scope_hash: @hash_schema,
      document_permission_proof_hash: @hash_schema,
      delivery_mode: %Schema{type: :string, enum: ["unknown_fragment", "known_recipient"]},
      encryption_key_id: @hash_schema,
      event_hash: @hash_schema,
      event_sequence: %Schema{type: :integer, minimum: 1},
      event_type: %Schema{type: :string},
      exclusion_change_nonce: %Schema{type: :string},
      expires_event_sequence: %Schema{type: :integer, minimum: 1},
      expires_at_ms: %Schema{type: :integer, minimum: 1},
      guest_device_id: %Schema{type: :string},
      guest_encryption_key_id: @hash_schema,
      guest_grant_id: %Schema{type: :string},
      guest_invitation_id: %Schema{type: :string},
      guest_signing_key_id: @hash_schema,
      guest_user_id: %Schema{type: :string},
      invitation_id: %Schema{type: :string},
      invitee_binding: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          kind: %Schema{type: :string, enum: ["email"]},
          email_hash: @hash_schema
        },
        required: [:kind, :email_hash]
      },
      issued_at_ms: %Schema{type: :integer, minimum: 1},
      key_id: @hash_schema,
      key_checkpoint_hash: @hash_schema,
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_scope_id: %Schema{type: :string},
      key_scope_kind: %Schema{type: :string},
      key_material_hash: @hash_schema,
      key_version_context: @key_version_context_schema,
      kek_version: %Schema{type: :integer, minimum: 1},
      member_envelope_hash: @hash_schema,
      member_envelope_key_version: %Schema{type: :integer, minimum: 1},
      metadata_update_nonce: %Schema{type: :string},
      min_dek_version: %Schema{type: :integer, minimum: 1},
      max_views: %Schema{type: :integer, minimum: 1},
      max_ciphertext_bytes: %Schema{type: :integer, minimum: 1},
      max_update_count: %Schema{type: :integer, minimum: 1},
      new_key_version: %Schema{type: :integer, minimum: 1},
      new_identity_encryption_key_id: @hash_schema,
      new_identity_signing_key_id: @hash_schema,
      new_key_material_hash: @hash_schema,
      new_user_checkpoint_hash: @hash_schema,
      not_before_event_sequence: %Schema{type: :integer, minimum: 1},
      old_identity_encryption_key_id: @hash_schema,
      old_identity_signing_key_id: @hash_schema,
      old_key_version: %Schema{type: :integer, minimum: 1},
      old_user_checkpoint_hash: @hash_schema,
      old_user_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      operation_checkpoint_hash: @hash_schema,
      operation_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      operation_hash: @hash_schema,
      operation_signature_hash: @hash_schema,
      parent_share_id: %Schema{type: :string},
      password_auth_metadata_hash: %Schema{
        oneOf: [@hash_schema, %Schema{type: :string, enum: ["none"]}]
      },
      password_capability_secret_commitment: %Schema{
        oneOf: [@hash_schema, %Schema{type: :string, enum: ["none"]}]
      },
      password_protected: %Schema{type: :boolean},
      permission: %Schema{type: :string},
      previous_workspace_event_hash: @hash_schema,
      previous_workspace_event_sequence: %Schema{type: :integer, minimum: 1},
      previous_share_key_version: %Schema{type: :integer, minimum: 1},
      previous_share_scope_event_hash: @hash_schema,
      previous_write_state: %Schema{
        type: :string,
        enum: ["writable", "read_only", "archived", "write_disabled"]
      },
      principal_id: %Schema{type: :string},
      purpose: %Schema{type: :string},
      reason: %Schema{type: :string},
      recipient: @extension_context_schema,
      recipient_account_device_id: %Schema{type: :string, nullable: true},
      recipient_account_user_id: %Schema{type: :string, nullable: true},
      recipient_device_ids: %Schema{type: :array, items: %Schema{type: :string}},
      recipient_user_id: %Schema{type: :string, nullable: true},
      redeemed_at_event_sequence: %Schema{type: :integer, minimum: 1},
      redeemed_device_id: %Schema{type: :string},
      redeemed_encryption_key_id: @hash_schema,
      redeemed_user_id: %Schema{type: :string},
      removed_at_event_sequence: %Schema{type: :integer, minimum: 1},
      removed_reason: %Schema{
        type: :string,
        enum: [
          "moved_out_of_share_root",
          "share_exclusion_added",
          "document_deleted",
          "folder_deleted",
          "share_root_deleted"
        ]
      },
      removed_scope_hashes: %Schema{type: :array, items: @hash_schema},
      replaced_at_event_sequence: %Schema{type: :integer, minimum: 1},
      required_authority: %Schema{type: :string},
      redeem_authority: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          signer_kind: %Schema{
            type: :string,
            enum: ["invitation_redeem_authority"]
          },
          signing_key_id: @hash_schema,
          hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial
        },
        required: [
          :signer_kind,
          :signing_key_id,
          :hybrid_signing_public_key_material
        ]
      },
      redeem_authority_policy: %Schema{type: :string},
      resource: @extension_context_schema,
      resource_hash: @hash_schema,
      revoked_at_event_sequence: %Schema{type: :integer, minimum: 1},
      role_id: %Schema{type: :string},
      rotation_kind: %Schema{type: :string},
      rotation_completed_event_hash: @hash_schema,
      scope_id: %Schema{type: :string},
      scope_kind: %Schema{type: :string},
      sender: @extension_context_schema,
      session_id: @hash_schema,
      session_nonce: @hash_schema,
      share_authority_kind: %Schema{type: :string},
      share_capability_secret_commitment: @hash_schema,
      share_id: %Schema{type: :string},
      share_key_version: %Schema{type: :integer, minimum: 1},
      share_metadata_hash: @hash_schema,
      share_permission: %Schema{type: :string},
      share_session_id: %Schema{type: :string},
      signer_kind: %Schema{type: :string},
      signing_key_id: @hash_schema,
      user_id: %Schema{type: :string},
      updated_at_event_sequence: %Schema{type: :integer, minimum: 1},
      workspace_id: %Schema{type: :string},
      write_state: %Schema{
        type: :string,
        enum: ["writable", "read_only", "archived", "write_disabled"]
      },
      wrap_body_hash: @hash_schema,
      wrap_protocol: %Schema{type: :string},
      wrap_suite_id: %Schema{type: :string},
      wrap_suite_rank: %Schema{type: :integer, minimum: 1},
      wrap_version: %Schema{type: :integer, minimum: 1}
    }
  }
  @event_ref_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      scope_id: %Schema{type: :string},
      event_sequence: %Schema{type: :integer, minimum: 1},
      event_hash: @hash_schema
    },
    required: [:scope_kind, :scope_id, :event_sequence, :event_hash]
  }
  @event_head_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      head_sequence: %Schema{type: :integer, minimum: 1},
      head_hash: @hash_schema
    },
    required: [:head_sequence, :head_hash]
  }
  @identity_key_entry_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      key_id: @hash_schema,
      key_material: %Schema{
        oneOf: [
          RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
          RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial
        ]
      },
      valid_from: @event_ref_schema,
      revoked_at: @event_ref_schema
    },
    required: [:key_id, :key_material, :valid_from]
  }
  @device_key_entry_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      key_id: @hash_schema,
      key_material: %Schema{
        oneOf: [
          RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
          RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial
        ]
      },
      valid_from: @event_ref_schema,
      revoked_at: @event_ref_schema
    },
    required: [:key_id, :key_material, :valid_from]
  }
  @share_participant_key_entry_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      key_id: @hash_schema,
      key_material: %Schema{
        oneOf: [
          RefMDWeb.Schemas.ShareParticipantDeviceSigningPublicKeyMaterial,
          RefMDWeb.Schemas.ShareParticipantDeviceEncryptionPublicKeyMaterial
        ]
      },
      valid_from: @event_ref_schema,
      revoked_at: @event_ref_schema
    },
    required: [:key_id, :key_material, :valid_from]
  }
  @identity_signer_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["identity"]},
      user_id: %Schema{type: :string},
      signing_key_id: @hash_schema,
      key_scope_kind: %Schema{type: :string},
      key_scope_id: %Schema{type: :string},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema,
      authorizing_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      authorizing_checkpoint_hash: @hash_schema,
      role_at_event: %Schema{type: :string}
    },
    required: [:signer_kind, :user_id, :signing_key_id]
  }
  @device_signer_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["device"]},
      user_id: %Schema{type: :string},
      device_id: %Schema{type: :string},
      signing_key_id: @hash_schema,
      key_scope_kind: %Schema{type: :string},
      key_scope_id: %Schema{type: :string},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema,
      authorizing_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      authorizing_checkpoint_hash: @hash_schema,
      role_at_event: %Schema{type: :string}
    },
    required: [:signer_kind, :user_id, :device_id, :signing_key_id]
  }
  @share_participant_device_signer_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["share_participant_device"]},
      signing_key_id: @hash_schema,
      share_id: %Schema{type: :string},
      share_participant_device_id: %Schema{type: :string},
      share_participant_principal_id: %Schema{type: :string},
      key_scope_kind: %Schema{type: :string},
      key_scope_id: %Schema{type: :string},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema,
      authorizing_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      authorizing_checkpoint_hash: @hash_schema,
      role_at_event: %Schema{type: :string}
    },
    required: [
      :signer_kind,
      :share_id,
      :share_participant_principal_id,
      :share_participant_device_id,
      :signing_key_id
    ]
  }
  @invitation_redeem_signer_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["invitation_redeem_authority"]},
      invitation_id: %Schema{type: :string},
      signing_key_id: @hash_schema,
      key_scope_kind: %Schema{type: :string},
      key_scope_id: %Schema{type: :string},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema,
      authorizing_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      authorizing_checkpoint_hash: @hash_schema,
      role_at_event: %Schema{type: :string}
    },
    required: [:signer_kind, :invitation_id, :signing_key_id]
  }
  @signature_signer_schema %Schema{
    oneOf: [
      @identity_signer_schema,
      @device_signer_schema,
      @share_participant_device_signer_schema,
      @invitation_redeem_signer_schema
    ]
  }
  @signature_envelope_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer: @signature_signer_schema,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:signer, :signature]
  }

  body_field_atoms =
    Map.new(
      [
        :actor_hash,
        :added_at_event_sequence,
        :added_scope_hashes,
        :admission_nonce,
        :allowed_share_ids_hash,
        :allowed_suite_ids,
        :authorization_hash,
        :authorization_id,
        :authorization_public_key_material,
        :authorization_public_key_material_hash,
        :authority_kind,
        :authority_scope_id,
        :base_role,
        :bootstrap_key_commitment,
        :bootstrap_package_hash,
        :bootstrap_package_key_maintenance_wrap_hash,
        :bootstrap_suite_id,
        :capability_context_hash,
        :changed_at_event_sequence,
        :completed_at_event_sequence,
        :completion_manifest_hash,
        :context_id,
        :context_kind,
        :dek_version,
        :deleted_at_event_sequence,
        :deletion_manifest_hash,
        :delivery_mode,
        :device_id,
        :document_id,
        :document_permission_proof_hash,
        :document_scope_hash,
        :encryption_key_id,
        :event_type,
        :exclusion_change_nonce,
        :expires_event_sequence,
        :expires_at_ms,
        :guest_device_id,
        :guest_encryption_key_id,
        :guest_grant_id,
        :guest_grant_template_hash,
        :guest_invitation_id,
        :guest_signing_key_id,
        :guest_user_id,
        :invitation_id,
        :invitee_binding,
        :issued_at_ms,
        :kek_version,
        :key_id,
        :key_kind,
        :key_material_hash,
        :key_version_context,
        :live_redeem_challenge_hash,
        :max_views,
        :max_ciphertext_bytes,
        :max_update_count,
        :member_envelope_hash,
        :member_envelope_key_version,
        :metadata_update_nonce,
        :min_dek_version,
        :min_suite_rank,
        :new_key_version,
        :new_identity_encryption_key_id,
        :new_identity_signing_key_id,
        :new_key_material_hash,
        :new_user_checkpoint_hash,
        :not_before_event_sequence,
        :old_identity_encryption_key_id,
        :old_identity_signing_key_id,
        :old_key_version,
        :old_user_checkpoint_hash,
        :old_user_checkpoint_sequence,
        :operation_hash,
        :operation_signature_hash,
        :parent_share_id,
        :password_auth_metadata_hash,
        :password_capability_secret_commitment,
        :password_protected,
        :permission,
        :permission_version,
        :previous_bootstrap_package_hash,
        :previous_base_role,
        :previous_effective_permissions,
        :previous_role_id,
        :previous_share_key_version,
        :previous_share_scope_event_hash,
        :previous_workspace_event_hash,
        :previous_workspace_event_sequence,
        :previous_write_state,
        :purpose,
        :reason,
        :recipient,
        :recipient_account_device_id,
        :recipient_account_user_id,
        :recipient_device_id,
        :recipient_device_ids,
        :recipient_hash,
        :recipient_nonce_state_hash,
        :recipient_user_id,
        :redeem_attempt_id,
        :redeem_authority,
        :redeem_authority_policy,
        :redeem_freshness_proof_hash,
        :redeemed_at_event_sequence,
        :redeemed_device_id,
        :redeemed_encryption_key_id,
        :redeemed_user_id,
        :removed_at_event_sequence,
        :removed_reason,
        :removed_scope_hashes,
        :replaced_at_event_sequence,
        :resource,
        :resource_hash,
        :revoked_at_event_sequence,
        :role_id,
        :rotation_kind,
        :rotation_completed_event_hash,
        :scope_id,
        :scope_kind,
        :sender,
        :session_id,
        :session_nonce,
        :share_authority_kind,
        :share_capability_secret_commitment,
        :share_id,
        :share_key_version,
        :share_metadata_hash,
        :share_permission,
        :share_session_binding_hash,
        :share_session_id,
        :signing_key_id,
        :suite_policy_version,
        :update_reason,
        :updated_at_event_sequence,
        :user_id,
        :workspace_id,
        :effective_permissions,
        :write_state,
        :wrap_body_hash,
        :wrap_protocol,
        :wrap_suite_id,
        :wrap_suite_rank,
        :wrap_version
      ],
      &{Atom.to_string(&1), &1}
    )

  body_field_atom = fn field -> Map.fetch!(body_field_atoms, field) end

  body_schema = fn fields ->
    properties =
      fields
      |> Map.new(fn field ->
        atom_field = body_field_atom.(field)

        {atom_field,
         Map.get(@extension_object_schema.properties, atom_field, %Schema{
           type: :string
         })}
      end)

    %Schema{
      type: :object,
      additionalProperties: false,
      properties: properties,
      required: Enum.map(fields, body_field_atom)
    }
  end

  body_schema_with_overrides = fn fields, overrides ->
    schema = body_schema.(fields)
    %{schema | properties: Map.merge(schema.properties, overrides)}
  end

  event_schema_with_body = fn event_type, body ->
    properties = %{
      protocol: %Schema{type: :string, enum: ["refmd.key-directory-event"]},
      version: %Schema{type: :integer, enum: [1]},
      scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      scope_id: %Schema{type: :string},
      event_type: %Schema{type: :string, enum: [event_type]},
      actor: @signature_signer_schema,
      body: body
    }

    required = [
      :protocol,
      :version,
      :scope_kind,
      :scope_id,
      :sequence,
      :event_type,
      :actor,
      :body
    ]

    initial_event_schema = %Schema{
      type: :object,
      additionalProperties: false,
      properties: Map.put(properties, :sequence, %Schema{type: :integer, enum: [1]}),
      required: required
    }

    append_event_schema = %Schema{
      type: :object,
      additionalProperties: false,
      properties:
        properties
        |> Map.put(:sequence, %Schema{type: :integer, minimum: 2})
        |> Map.put(:previous_event_hash, @hash_schema),
      required: [:previous_event_hash | required]
    }

    %Schema{
      oneOf: [initial_event_schema, append_event_schema]
    }
  end

  event_schema = fn event_type, fields ->
    event_schema_with_body.(event_type, body_schema.(fields))
  end

  strict_event_schema = fn event_type, fields, body_overrides ->
    event_schema_with_body.(
      event_type,
      body_schema_with_overrides.(fields, body_overrides)
    )
  end

  @event_payload_schema %Schema{
    oneOf: [
      event_schema.("device_key_added", [
        "encryption_key_id",
        "signing_key_id",
        "user_id",
        "device_id"
      ]),
      strict_event_schema.(
        "identity_key_added",
        ["key_kind", "key_id", "key_material_hash"],
        %{key_kind: %Schema{type: :string, enum: ["signing", "encryption"]}}
      ),
      event_schema.("signing_key_revoked", ["key_id", "reason", "revoked_at_event_sequence"]),
      event_schema.("encryption_key_revoked", [
        "key_id",
        "reason",
        "revoked_at_event_sequence"
      ]),
      event_schema.("suite_policy_changed", [
        "allowed_suite_ids",
        "min_suite_rank",
        "suite_policy_version"
      ]),
      event_schema.("member_added", ["base_role", "role_id", "user_id", "workspace_id"]),
      strict_event_schema.(
        "member_role_changed",
        [
          "workspace_id",
          "user_id",
          "previous_role_id",
          "previous_base_role",
          "previous_effective_permissions",
          "role_id",
          "base_role",
          "effective_permissions",
          "permission_version",
          "changed_at_event_sequence"
        ],
        %{
          previous_base_role: %Schema{
            type: :string,
            enum: ["owner", "admin", "editor", "viewer"]
          },
          previous_effective_permissions: %Schema{
            type: :array,
            items: %Schema{type: :string}
          },
          base_role: %Schema{
            type: :string,
            enum: ["owner", "admin", "editor", "viewer"]
          },
          effective_permissions: %Schema{type: :array, items: %Schema{type: :string}},
          permission_version: %Schema{type: :integer, minimum: 1},
          changed_at_event_sequence: %Schema{type: :integer, minimum: 1}
        }
      ),
      event_schema.("member_removed", ["removed_at_event_sequence", "user_id", "workspace_id"]),
      event_schema.("wrap_issued", [
        "purpose",
        "recipient",
        "resource",
        "resource_hash",
        "sender",
        "wrap_body_hash",
        "wrap_protocol",
        "wrap_suite_id",
        "wrap_suite_rank",
        "wrap_version"
      ]),
      event_schema.("workspace_invitation_created", [
        "workspace_id",
        "invitation_id",
        "invitee_binding",
        "role_id",
        "base_role",
        "delivery_mode",
        "recipient_user_id",
        "recipient_device_ids",
        "kek_version",
        "expires_event_sequence",
        "redeem_authority",
        "bootstrap_key_commitment",
        "bootstrap_package_hash",
        "bootstrap_suite_id",
        "capability_context_hash"
      ]),
      event_schema.("workspace_invitation_revoked", [
        "workspace_id",
        "invitation_id",
        "revoked_at_event_sequence",
        "reason"
      ]),
      event_schema.("workspace_invitation_bootstrap_updated", [
        "workspace_id",
        "invitation_id",
        "previous_bootstrap_package_hash",
        "bootstrap_package_hash",
        "bootstrap_package_key_maintenance_wrap_hash",
        "key_version_context",
        "updated_at_event_sequence",
        "update_reason"
      ]),
      event_schema.("workspace_invitation_redeemed", [
        "workspace_id",
        "invitation_id",
        "redeemed_user_id",
        "redeemed_device_id",
        "redeemed_encryption_key_id",
        "member_envelope_key_version",
        "member_envelope_hash",
        "redeemed_at_event_sequence"
      ]),
      event_schema.("guest_invitation_created", [
        "workspace_id",
        "guest_invitation_id",
        "guest_grant_template_hash",
        "scope_kind",
        "scope_id",
        "permission",
        "delivery_mode",
        "recipient_user_id",
        "recipient_device_ids",
        "key_version_context",
        "allowed_share_ids_hash",
        "expires_event_sequence",
        "redeem_authority",
        "bootstrap_key_commitment",
        "bootstrap_package_hash",
        "bootstrap_suite_id",
        "capability_context_hash"
      ]),
      event_schema.("guest_invitation_revoked", [
        "workspace_id",
        "guest_invitation_id",
        "revoked_at_event_sequence",
        "reason"
      ]),
      event_schema.("guest_invitation_bootstrap_updated", [
        "workspace_id",
        "guest_invitation_id",
        "scope_kind",
        "scope_id",
        "previous_bootstrap_package_hash",
        "bootstrap_package_hash",
        "bootstrap_package_key_maintenance_wrap_hash",
        "key_version_context",
        "updated_at_event_sequence",
        "update_reason"
      ]),
      event_schema.("guest_invitation_redeemed", [
        "workspace_id",
        "guest_invitation_id",
        "guest_grant_id",
        "guest_user_id",
        "guest_device_id",
        "guest_encryption_key_id",
        "guest_signing_key_id",
        "scope_kind",
        "scope_id",
        "permission",
        "recipient_account_user_id",
        "recipient_account_device_id",
        "redeemed_at_event_sequence"
      ]),
      event_schema.("guest_grant_revoked", [
        "workspace_id",
        "guest_grant_id",
        "guest_user_id",
        "scope_kind",
        "scope_id",
        "revoked_at_event_sequence",
        "reason"
      ]),
      event_schema.("guest_device_revoked", [
        "workspace_id",
        "guest_user_id",
        "guest_device_id",
        "guest_signing_key_id",
        "guest_encryption_key_id",
        "revoked_at_event_sequence",
        "reason"
      ]),
      event_schema.("share_created", [
        "workspace_id",
        "share_id",
        "scope_kind",
        "scope_id",
        "permission",
        "share_key_version",
        "password_protected",
        "authorization_public_key_material",
        "authorization_public_key_material_hash",
        "share_capability_secret_commitment",
        "password_capability_secret_commitment",
        "password_auth_metadata_hash",
        "max_views",
        "expires_event_sequence",
        "redeem_authority_policy",
        "capability_context_hash"
      ]),
      event_schema.("share_revoked", [
        "workspace_id",
        "share_id",
        "revoked_at_event_sequence",
        "reason"
      ]),
      event_schema.("share_metadata_updated", [
        "workspace_id",
        "share_id",
        "expires_event_sequence",
        "max_views",
        "updated_at_event_sequence",
        "metadata_update_nonce"
      ]),
      event_schema.("share_key_scope_added", [
        "workspace_id",
        "share_id",
        "parent_share_id",
        "scope_kind",
        "scope_id",
        "document_scope_hash",
        "share_metadata_hash",
        "share_key_version",
        "added_at_event_sequence"
      ]),
      event_schema.("share_key_scope_replaced", [
        "workspace_id",
        "share_id",
        "scope_kind",
        "scope_id",
        "document_scope_hash",
        "share_metadata_hash",
        "share_key_version",
        "previous_share_key_version",
        "replaced_at_event_sequence"
      ]),
      event_schema.("share_key_scope_removed", [
        "workspace_id",
        "share_id",
        "share_key_version",
        "scope_kind",
        "scope_id",
        "document_scope_hash",
        "removed_reason",
        "removed_at_event_sequence",
        "previous_share_scope_event_hash"
      ]),
      event_schema.("share_exclusion_changed", [
        "workspace_id",
        "share_id",
        "added_scope_hashes",
        "removed_scope_hashes",
        "changed_at_event_sequence",
        "exclusion_change_nonce"
      ]),
      event_schema.("recipient_bound_delivery_admitted", [
        "event_type",
        "authorization_id",
        "redeem_attempt_id",
        "authorization_hash",
        "workspace_id",
        "context_kind",
        "context_id",
        "recipient_hash",
        "recipient_device_id",
        "permission",
        "share_session_id",
        "share_session_binding_hash",
        "recipient_nonce_state_hash",
        "live_redeem_challenge_hash",
        "redeem_freshness_proof_hash",
        "previous_workspace_event_sequence",
        "previous_workspace_event_hash",
        "admission_nonce"
      ]),
      event_schema.("rotation_started", [
        "event_type",
        "new_key_version",
        "not_before_event_sequence",
        "old_key_version",
        "reason",
        "rotation_kind",
        "scope_id",
        "scope_kind"
      ]),
      event_schema.("rotation_started", [
        "event_type",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "old_identity_encryption_key_id",
        "new_identity_signing_key_id",
        "new_identity_encryption_key_id",
        "old_user_checkpoint_sequence",
        "old_user_checkpoint_hash",
        "new_key_material_hash",
        "reason",
        "not_before_event_sequence"
      ]),
      event_schema.("rotation_completed", [
        "completed_at_event_sequence",
        "completion_manifest_hash",
        "event_type",
        "new_key_version",
        "old_key_version",
        "rotation_kind",
        "scope_id",
        "scope_kind"
      ]),
      event_schema.("rotation_completed", [
        "event_type",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "new_identity_signing_key_id",
        "old_user_checkpoint_hash",
        "new_user_checkpoint_hash",
        "completed_at_event_sequence",
        "completion_manifest_hash"
      ]),
      event_schema.("old_key_deleted", [
        "deleted_at_event_sequence",
        "deletion_manifest_hash",
        "event_type",
        "old_key_version",
        "rotation_kind",
        "scope_id",
        "scope_kind"
      ]),
      event_schema.("old_key_deleted", [
        "event_type",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "old_identity_encryption_key_id",
        "new_identity_signing_key_id",
        "rotation_completed_event_hash",
        "deleted_at_event_sequence",
        "deletion_manifest_hash"
      ]),
      event_schema.("document_snapshot_accepted", [
        "actor_hash",
        "admission_nonce",
        "dek_version",
        "document_id",
        "document_permission_proof_hash",
        "event_type",
        "min_dek_version",
        "operation_hash",
        "operation_signature_hash",
        "previous_workspace_event_hash",
        "previous_workspace_event_sequence",
        "workspace_id"
      ]),
      strict_event_schema.(
        "document_write_session_admitted",
        [
          "actor_hash",
          "authority_kind",
          "authority_scope_id",
          "document_id",
          "document_permission_proof_hash",
          "event_type",
          "expires_at_ms",
          "issued_at_ms",
          "max_ciphertext_bytes",
          "max_update_count",
          "min_dek_version",
          "previous_workspace_event_hash",
          "previous_workspace_event_sequence",
          "session_id",
          "session_nonce",
          "workspace_id"
        ],
        %{
          authority_kind: %Schema{type: :string, enum: ["workspace_device"]},
          event_type: %Schema{type: :string, enum: ["document_write_session_admitted"]}
        }
      ),
      strict_event_schema.(
        "document_write_session_admitted",
        [
          "actor_hash",
          "authority_kind",
          "authority_scope_id",
          "document_id",
          "document_permission_proof_hash",
          "event_type",
          "expires_at_ms",
          "issued_at_ms",
          "max_ciphertext_bytes",
          "max_update_count",
          "min_dek_version",
          "previous_workspace_event_hash",
          "previous_workspace_event_sequence",
          "session_id",
          "session_nonce",
          "share_authority_kind",
          "share_id",
          "share_permission",
          "share_session_id",
          "workspace_id"
        ],
        %{
          authority_kind: %Schema{type: :string, enum: ["share_participant_device"]},
          event_type: %Schema{type: :string, enum: ["document_write_session_admitted"]},
          share_authority_kind: %Schema{type: :string, enum: ["share_participant_device"]},
          share_permission: %Schema{type: :string, enum: ["edit"]}
        }
      ),
      event_schema.("document_write_state_changed", [
        "document_id",
        "event_type",
        "issued_at_ms",
        "previous_workspace_event_hash",
        "previous_workspace_event_sequence",
        "previous_write_state",
        "reason",
        "workspace_id",
        "write_state"
      ])
    ]
  }
  checkpoint_payload_schema = fn sequence_schema, previous_required? ->
    properties = %{
      protocol: %Schema{type: :string, enum: ["refmd.key-directory-checkpoint"]},
      version: %Schema{type: :integer, enum: [1]},
      scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      scope_id: %Schema{type: :string},
      sequence: sequence_schema,
      issued_at: %Schema{type: :string, format: :"date-time"},
      suite_policy_version: %Schema{type: :integer, minimum: 1},
      min_suite_rank: %Schema{type: :integer, minimum: 1},
      allowed_suite_ids: %Schema{type: :array, items: %Schema{type: :string}},
      required_components: %Schema{type: :array, items: %Schema{type: :string}},
      identity_keys: %Schema{type: :array, items: @identity_key_entry_schema},
      device_keys: %Schema{type: :array, items: @device_key_entry_schema},
      share_participant_keys: %Schema{type: :array, items: @share_participant_key_entry_schema},
      revoked_key_ids: %Schema{type: :array, items: @hash_schema},
      covered_event_head: @event_head_schema
    }

    required = [
      :protocol,
      :version,
      :scope_kind,
      :scope_id,
      :sequence,
      :issued_at,
      :suite_policy_version,
      :min_suite_rank,
      :allowed_suite_ids,
      :required_components,
      :identity_keys,
      :device_keys,
      :share_participant_keys,
      :revoked_key_ids,
      :covered_event_head
    ]

    {properties, required} =
      if previous_required? do
        {Map.put(properties, :previous_checkpoint_hash, @hash_schema),
         [:previous_checkpoint_hash | required]}
      else
        {properties, required}
      end

    %Schema{
      type: :object,
      additionalProperties: false,
      properties: properties,
      required: required
    }
  end

  @checkpoint_payload_schema %Schema{
    oneOf: [
      checkpoint_payload_schema.(%Schema{type: :integer, enum: [1]}, false),
      checkpoint_payload_schema.(%Schema{type: :integer, minimum: 2}, true)
    ]
  }

  OpenApiSpex.schema(%{
    title: "KeyDirectoryEnvelope",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: %Schema{oneOf: [@event_payload_schema, @checkpoint_payload_schema]},
      signatures: %Schema{type: :array, items: @signature_envelope_schema}
    },
    required: [:payload, :signatures]
  })
end

defmodule RefMDWeb.Schemas.WorkspacePinBootstrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  }
  @base64url_32_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43,
    description: "Strict unpadded base64url-encoded 32-byte value."
  }

  @issuer_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["device"]},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      signing_key_id: @hash_schema,
      key_scope_kind: %Schema{type: :string, enum: ["workspace"]},
      key_scope_id: %Schema{type: :string, format: :uuid},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema
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

  @payload_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.workspace-pin-bootstrap"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      checkpoint_hash: @hash_schema,
      event_head_sequence: %Schema{type: :integer, minimum: 0},
      event_head_hash: @hash_schema,
      suite_policy_version: %Schema{type: :integer, minimum: 1},
      min_suite_rank: %Schema{type: :integer, minimum: 1},
      allowed_suite_ids_hash: @hash_schema,
      issuer: @issuer_schema,
      issuing_event_hash: @hash_schema,
      expires_event_sequence: %Schema{type: :integer, minimum: 1},
      bootstrap_nonce: @base64url_32_schema
    },
    required: [
      :protocol,
      :version,
      :workspace_id,
      :checkpoint_sequence,
      :checkpoint_hash,
      :event_head_sequence,
      :event_head_hash,
      :suite_policy_version,
      :min_suite_rank,
      :allowed_suite_ids_hash,
      :issuer,
      :issuing_event_hash,
      :expires_event_sequence,
      :bootstrap_nonce
    ]
  }

  @signature_envelope_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer: @issuer_schema,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:signer, :signature]
  }

  OpenApiSpex.schema(%{
    title: "WorkspacePinBootstrap",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: @payload_schema,
      signatures: %Schema{type: :array, items: @signature_envelope_schema, minItems: 1}
    },
    required: [:payload, :signatures]
  })
end

defmodule RefMDWeb.Schemas.Base64UrlBytes do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "Base64UrlBytes",
    type: :string,
    pattern: "^[A-Za-z0-9_-]+$"
  })
end

defmodule RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "EncryptedIdentityHybridPrivateKeyMaterial",
    type: :string,
    pattern: "^[A-Za-z0-9_-]+$",
    description: "Strict base64url ciphertext for encrypted identity hybrid private key material."
  })
end

defmodule RefMDWeb.Schemas.XChaCha20Poly1305Nonce do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "XChaCha20Poly1305Nonce",
    type: :string,
    pattern: "^[A-Za-z0-9_-]{32}$",
    minLength: 32,
    maxLength: 32
  })
end

defmodule RefMDWeb.Schemas.EncryptedMaterialNonce do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "EncryptedMaterialNonce",
    type: :string,
    pattern: "^[A-Za-z0-9_-]{32}$",
    minLength: 32,
    maxLength: 32,
    description: "Strict base64url 24-byte XChaCha20-Poly1305 nonce for encrypted material."
  })
end

defmodule RefMDWeb.Schemas.HybridKeyWrapFields do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @hash_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  }
  @base64url_schema %Schema{type: :string, pattern: "^[A-Za-z0-9_-]+$"}
  @wrap_suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @wrap_purposes [
    "workspace_device_kek_wrap",
    "workspace_member_kek_wrap",
    "share_participant_bootstrap_wrap",
    "share_link_secret_backup_wrap",
    "workspace_invitation_kek_wrap",
    "guest_invitation_workspace_kek_wrap",
    "guest_invitation_share_key_wrap"
  ]
  @event_scope_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      scope_kind: %Schema{type: :string, enum: ["user", "workspace", "document", "folder"]},
      scope_id: %Schema{type: :string}
    },
    required: [:scope_kind, :scope_id]
  }
  @wrap_sender_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["device"]},
      user_id: %Schema{type: :string},
      device_id: %Schema{type: :string},
      signing_key_id: @hash_schema,
      key_scope_kind: %Schema{type: :string, enum: ["user", "workspace", "document", "folder"]},
      key_scope_id: %Schema{type: :string},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema
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
  @wrap_recipient_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      recipient_kind: %Schema{
        type: :string,
        enum: ["device", "user_identity", "invitee", "guest", "share_participant_device"]
      },
      user_id: %Schema{type: :string},
      device_id: %Schema{type: :string},
      invitee_user_id: %Schema{type: :string},
      invitee_device_id: %Schema{type: :string},
      guest_user_id: %Schema{type: :string},
      guest_device_id: %Schema{type: :string},
      share_participant_principal_id: %Schema{type: :string},
      share_participant_device_id: %Schema{type: :string},
      encryption_key_id: @hash_schema,
      key_scope_kind: %Schema{type: :string, enum: ["user", "workspace", "document", "folder"]},
      key_scope_id: %Schema{type: :string},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: @hash_schema
    },
    required: [
      :recipient_kind,
      :encryption_key_id,
      :key_scope_kind,
      :key_scope_id,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  }

  resource_schema = fn required, properties ->
    base =
      required
      |> Map.new(fn field ->
        {field, %Schema{type: :string}}
      end)
      |> Map.merge(properties)

    %Schema{
      type: :object,
      additionalProperties: false,
      properties: base,
      required: required
    }
  end

  @resource_schema %Schema{
    oneOf: [
      resource_schema.([:workspace_id, :target_user_id, :target_device_id, :kek_version], %{
        kek_version: %Schema{type: :integer, minimum: 1}
      }),
      resource_schema.([:workspace_id, :target_user_id, :kek_version], %{
        kek_version: %Schema{type: :integer, minimum: 1}
      }),
      resource_schema.(
        [
          :workspace_id,
          :share_id,
          :share_participant_principal_id,
          :share_participant_device_id,
          :scope_kind,
          :scope_id,
          :permission,
          :document_scope_hash,
          :share_session_id,
          :share_key_version,
          :dek_version,
          :bootstrap_version
        ],
        %{
          scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
          permission: %Schema{type: :string, enum: ["view", "edit"]},
          document_scope_hash: @hash_schema,
          share_key_version: %Schema{type: :integer, minimum: 1},
          dek_version: %Schema{type: :integer, minimum: 1},
          bootstrap_version: %Schema{type: :integer, minimum: 1}
        }
      ),
      resource_schema.(
        [
          :workspace_id,
          :share_id,
          :token_hash,
          :scope_kind,
          :scope_id,
          :permission,
          :password_protected,
          :created_event_hash,
          :share_capability_secret_commitment,
          :password_capability_secret_commitment,
          :workspace_pin_bootstrap_hash,
          :recipient_user_id,
          :recipient_device_id,
          :recipient_encryption_key_id,
          :key_checkpoint_hash
        ],
        %{
          token_hash: @hash_schema,
          scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
          permission: %Schema{type: :string, enum: ["view", "edit"]},
          password_protected: %Schema{type: :boolean},
          created_event_hash: @hash_schema,
          share_capability_secret_commitment: @hash_schema,
          password_capability_secret_commitment: %Schema{
            oneOf: [@hash_schema, %Schema{type: :string, enum: ["none"]}]
          },
          workspace_pin_bootstrap_hash: @hash_schema,
          key_checkpoint_hash: @hash_schema
        }
      ),
      resource_schema.(
        [
          :workspace_id,
          :invitation_id,
          :redeemed_user_id,
          :redeemed_device_id,
          :recipient_encryption_key_id,
          :role_id,
          :kek_version,
          :workspace_invitation_redeemed_event_hash
        ],
        %{
          kek_version: %Schema{type: :integer, minimum: 1},
          workspace_invitation_redeemed_event_hash: @hash_schema
        }
      ),
      resource_schema.(
        [
          :workspace_id,
          :guest_invitation_id,
          :guest_user_id,
          :guest_device_id,
          :recipient_encryption_key_id,
          :guest_grant_id,
          :scope_kind,
          :scope_id,
          :permission,
          :kek_version,
          :guest_invitation_redeemed_event_hash
        ],
        %{
          scope_kind: %Schema{type: :string, enum: ["workspace"]},
          scope_id: %Schema{type: :string, enum: ["none"]},
          permission: %Schema{type: :string, enum: ["view", "edit"]},
          kek_version: %Schema{type: :integer, minimum: 1},
          guest_invitation_redeemed_event_hash: @hash_schema
        }
      ),
      resource_schema.(
        [
          :workspace_id,
          :guest_invitation_id,
          :guest_user_id,
          :guest_device_id,
          :recipient_encryption_key_id,
          :share_id,
          :scope_kind,
          :scope_id,
          :permission,
          :document_scope_hash,
          :share_key_version,
          :dek_version,
          :guest_invitation_redeemed_event_hash
        ],
        %{
          scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
          permission: %Schema{type: :string, enum: ["view", "edit"]},
          document_scope_hash: @hash_schema,
          share_key_version: %Schema{type: :integer, minimum: 1},
          dek_version: %Schema{type: :integer, minimum: 1},
          guest_invitation_redeemed_event_hash: @hash_schema
        }
      )
    ]
  }

  OpenApiSpex.schema(%{
    title: "HybridKeyWrapFields",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.signed-pq-hybrid-wrap"]},
      protocol_version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, enum: [@wrap_suite_id]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      purpose: %Schema{type: :string, enum: @wrap_purposes},
      resource: @resource_schema,
      sender: @wrap_sender_schema,
      recipient: @wrap_recipient_schema,
      event_scope: @event_scope_schema,
      event: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          wrap_event_sequence: %Schema{type: :integer},
          wrap_event_hash: @hash_schema,
          wrap_event_body_hash: @hash_schema
        },
        required: [:wrap_event_sequence, :wrap_event_hash, :wrap_event_body_hash]
      },
      operation_checkpoint: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          checkpoint_sequence: %Schema{type: :integer},
          checkpoint_hash: @hash_schema,
          covered_event_head_sequence: %Schema{type: :integer},
          covered_event_head_hash: @hash_schema
        },
        required: [
          :checkpoint_sequence,
          :checkpoint_hash,
          :covered_event_head_sequence,
          :covered_event_head_hash
        ]
      },
      hpke: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          mode: %Schema{type: :string, enum: ["base"]},
          kem_id: %Schema{type: :integer, enum: [0x647A]},
          kdf_id: %Schema{type: :integer, enum: [0x0001]},
          aead_id: %Schema{type: :integer, enum: [0x0003]},
          enc: %Schema{
            type: :string,
            pattern: "^[A-Za-z0-9_-]+$",
            minLength: 1494,
            maxLength: 1494
          },
          ciphertext: @base64url_schema
        },
        required: [:mode, :kem_id, :kdf_id, :aead_id, :enc, :ciphertext]
      },
      transcript_hash: @hash_schema,
      signature: RefMDWeb.Schemas.HybridSignature
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
      :event,
      :operation_checkpoint,
      :hpke,
      :transcript_hash,
      :signature
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceOperationProvenSignedPqWrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceOperationProvenSignedPqWrap",
    allOf: [
      RefMDWeb.Schemas.HybridKeyWrapFields,
      %Schema{
        type: :object,
        properties: %{
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
          :workspace_key_directory_checkpoint,
          :workspace_key_directory_checkpoint_ancestry,
          :workspace_key_directory_event_ancestry
        ]
      }
    ]
  })
end
