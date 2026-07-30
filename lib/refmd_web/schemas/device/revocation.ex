defmodule RefMDWeb.Schemas.DeviceRevocationCommand do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRevocationCommand",
    type: :object,
    additionalProperties: false,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      revocation_mode: %Schema{type: :string, enum: ["security", "retire"]}
    },
    required: [:device_id, :revocation_mode]
  })
end

defmodule RefMDWeb.Schemas.DeviceRevocationEffectAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRevocationEffectAuthorization",
    type: :object,
    additionalProperties: false,
    properties: %{
      requirement_order: %Schema{type: :integer, minimum: 1},
      authorization_kind: %Schema{
        type: :string,
        enum: ["key_directory_event", "key_directory_checkpoint", "device_revocation", "pq_wrap"]
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

defmodule RefMDWeb.Schemas.DeviceRevocationAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRevocationAuthorization",
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
        minItems: 4,
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

defmodule RefMDWeb.Schemas.WorkspaceRotationInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceRotationInfo",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      current_kek_version: %Schema{type: :integer},
      kek_rotation_initiator_user_id: %Schema{type: :string, format: :uuid, nullable: true},
      rotation_id: %Schema{type: :string, format: :uuid, nullable: true},
      pending_kek_version: %Schema{type: :integer, minimum: 1, nullable: true}
    },
    required: [
      :workspace_id,
      :current_kek_version,
      :kek_rotation_initiator_user_id,
      :rotation_id,
      :pending_kek_version
    ]
  })
end

defmodule RefMDWeb.Schemas.RemoveMemberResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RemoveMemberResponse",
    type: :object,
    additionalProperties: false,
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

defmodule RefMDWeb.Schemas.RevokeDeviceResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RevokeDeviceResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      status: %Schema{type: :string, enum: ["committed"]},
      revoked_device_id: %Schema{type: :string, format: :uuid},
      revocation_mode: %Schema{type: :string, enum: ["security", "retire"]},
      user_key_directory_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      user_audit_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspaces_needing_kek_rotation: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceRotationInfo
      }
    },
    required: [
      :status,
      :revoked_device_id,
      :revocation_mode,
      :user_key_directory_checkpoint_hash,
      :user_audit_checkpoint_hash,
      :workspaces_needing_kek_rotation
    ]
  })
end
