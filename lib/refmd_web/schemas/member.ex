defmodule RefMDWeb.Schemas.MemberInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberInfo",
    type: :object,
    properties: %{
      user_id: %Schema{type: :string, format: :uuid},
      email: %Schema{type: :string, format: :email},
      name: %Schema{type: :string},
      role_id: %Schema{type: :string, format: :uuid},
      role_name: %Schema{type: :string},
      base_role: %Schema{type: :string, enum: ["owner", "admin", "editor", "viewer", "guest"]},
      is_default: %Schema{type: :boolean},
      permission_version: %Schema{type: :integer, minimum: 1},
      joined_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :user_id,
      :email,
      :name,
      :role_id,
      :role_name,
      :base_role,
      :permission_version,
      :joined_at
    ]
  })
end

defmodule RefMDWeb.Schemas.ChangeMemberRoleResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ChangeMemberRoleResponse",
    type: :object,
    properties: %{
      ok: %Schema{type: :boolean},
      workspaces_needing_kek_rotation: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceRotationInfo
      }
    },
    required: [:ok, :workspaces_needing_kek_rotation]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceAuthorityMutationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceAuthorityMutationResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      status: %Schema{type: :string, enum: ["committed"]},
      event_type: %Schema{
        type: :string,
        enum: [
          "workspace.member.role_changed",
          "workspace.member.removed",
          "workspace.kek.rotation_started",
          "workspace.kek.rotation_completed",
          "workspace.kek.old_key_deleted"
        ]
      },
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_key_directory_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspace_audit_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      permission_loss: %Schema{type: :boolean},
      workspaces_needing_kek_rotation: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceRotationInfo
      }
    },
    required: [
      :status,
      :event_type,
      :workspace_id,
      :workspace_key_directory_checkpoint_hash,
      :workspace_audit_checkpoint_hash,
      :permission_loss,
      :workspaces_needing_kek_rotation
    ]
  })
end

defmodule RefMDWeb.Schemas.MembersListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MembersListResponse",
    type: :object,
    properties: %{
      members: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.MemberInfo}
    },
    required: [:members]
  })
end

defmodule RefMDWeb.Schemas.MemberDeviceInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberDeviceInfo",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      hybrid_encryption_public_key_material: RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      encryption_key_id: %Schema{type: :string},
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
      client_nonce: %Schema{type: :string},
      revoked_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :device_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :client_nonce,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.MemberDevicesResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberDevicesResponse",
    type: :object,
    properties: %{
      devices: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.MemberDeviceInfo}
    },
    required: [:devices]
  })
end

defmodule RefMDWeb.Schemas.MemberRoleIntentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberRoleIntentRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      role_id: %Schema{type: :string, format: :uuid}
    },
    required: [:role_id]
  })
end

defmodule RefMDWeb.Schemas.MemberRemovalIntentRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberRemovalIntentRequest",
    type: :object,
    additionalProperties: false,
    properties: %{}
  })
end

defmodule RefMDWeb.Schemas.CompoundAppendIntent do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CompoundAppendIntent",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.audit.compound-append-intent"]},
      version: %Schema{type: :integer, enum: [1]},
      compound_intent_id: %Schema{type: :string, format: :uuid},
      mutation_id: %Schema{type: :string, format: :uuid},
      challenge_id: %Schema{type: :string, format: :uuid},
      expires_at: %Schema{type: :string, format: :"date-time"},
      key_directory_effects_hash: RefMDWeb.Schemas.Blake3Base64Url,
      scopes: %Schema{type: :array, minItems: 1, items: %Schema{type: :object}}
    },
    required: [
      :protocol,
      :version,
      :compound_intent_id,
      :mutation_id,
      :challenge_id,
      :expires_at,
      :key_directory_effects_hash,
      :scopes
    ]
  })
end

defmodule RefMDWeb.Schemas.CompoundAppendAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CompoundAppendAuthorization",
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
        minItems: 1,
        maxItems: 1,
        items: RefMDWeb.Schemas.GenesisScopeSignature
      },
      effect_authorizations: %Schema{
        type: :array,
        minItems: 2,
        items: RefMDWeb.Schemas.DeviceRevocationEffectAuthorization
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
