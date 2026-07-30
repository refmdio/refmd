defmodule RefMDWeb.Schemas.GuestInvitationKeyVersionContext do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GuestInvitationKeyVersionContext",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_kek_version: %Schema{
        oneOf: [
          %Schema{type: :integer, minimum: 1},
          %Schema{type: :string, enum: ["NOT_APPLICABLE"]}
        ]
      },
      share_key_version: %Schema{
        oneOf: [
          %Schema{type: :integer, minimum: 1},
          %Schema{type: :string, enum: ["NOT_APPLICABLE"]}
        ]
      },
      dek_version: %Schema{
        oneOf: [
          %Schema{type: :integer, minimum: 1},
          %Schema{type: :string, enum: ["NOT_APPLICABLE"]}
        ]
      }
    },
    required: [:workspace_kek_version, :share_key_version, :dek_version]
  })
end

defmodule RefMDWeb.Schemas.GuestInvitationBootstrapAad do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GuestInvitationBootstrapAad",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.guest-invitation-bootstrap"]},
      version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      guest_invitation_id: %Schema{type: :string, format: :uuid},
      scope_kind: %Schema{type: :string, enum: ["workspace", "document", "folder", "share"]},
      scope_id: %Schema{type: :string},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      delivery_mode: %Schema{type: :string, enum: ["unknown_fragment", "known_recipient"]},
      recipient_user_id: %Schema{
        oneOf: [
          %Schema{type: :string, format: :uuid},
          %Schema{type: :string, enum: ["NOT_APPLICABLE"]}
        ]
      },
      recipient_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      },
      key_version_context: RefMDWeb.Schemas.GuestInvitationKeyVersionContext,
      token_hash: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :suite_id,
      :workspace_id,
      :guest_invitation_id,
      :scope_kind,
      :scope_id,
      :permission,
      :delivery_mode,
      :recipient_device_ids,
      :key_version_context,
      :token_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.GuestInvitationBootstrapPackage do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GuestInvitationBootstrapPackage",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.guest-invitation-bootstrap"]},
      version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer, minimum: 1},
      aad: RefMDWeb.Schemas.GuestInvitationBootstrapAad,
      encrypted_payload: RefMDWeb.Schemas.InvitationBootstrapCiphertext,
      package_key_recipient_wrap: RefMDWeb.Schemas.InvitationPackageKeyRecipientWrap,
      package_key_maintenance_wrap: RefMDWeb.Schemas.InvitationBootstrapMaintenanceWrap
    },
    required: [
      :protocol,
      :version,
      :suite_id,
      :workspace_id,
      :key_version,
      :aad,
      :encrypted_payload,
      :package_key_recipient_wrap,
      :package_key_maintenance_wrap
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateGuestInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateGuestInvitationRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      token_hash: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      scope_kind: %Schema{type: :string, enum: ["workspace", "document", "folder", "share"]},
      scope_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_id: %Schema{type: :string, format: :uuid, nullable: true},
      key_version_context: RefMDWeb.Schemas.GuestInvitationKeyVersionContext,
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      invited_email: %Schema{type: :string, format: :email, nullable: true},
      delivery_mode: %Schema{type: :string, enum: ["unknown_fragment", "known_recipient"]},
      recipient_user_id: %Schema{type: :string, format: :uuid, nullable: true},
      recipient_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      },
      bootstrap_key_commitment: %Schema{type: :string},
      encrypted_bootstrap_package: RefMDWeb.Schemas.GuestInvitationBootstrapPackage,
      bootstrap_package_hash: %Schema{type: :string},
      bootstrap_package_key_recipient_wrap: RefMDWeb.Schemas.InvitationPackageKeyRecipientWrap,
      bootstrap_package_key_maintenance_wrap: RefMDWeb.Schemas.InvitationBootstrapMaintenanceWrap,
      bootstrap_suite_id: %Schema{
        type: :string,
        enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]
      },
      capability_context_hash: %Schema{type: :string},
      max_redemptions: %Schema{type: :integer, nullable: true},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :invitation_id,
      :token_hash,
      :token_prefix,
      :scope_kind,
      :key_version_context,
      :permission,
      :delivery_mode,
      :recipient_device_ids,
      :bootstrap_key_commitment,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :bootstrap_package_key_recipient_wrap,
      :bootstrap_package_key_maintenance_wrap,
      :bootstrap_suite_id,
      :capability_context_hash,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.GuestInvitationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GuestInvitationResponse",
    type: :object,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      token_prefix: %Schema{type: :string},
      scope_kind: %Schema{type: :string, enum: ["workspace", "document", "folder", "share"]},
      scope_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_id: %Schema{type: :string, format: :uuid, nullable: true},
      key_version_context: RefMDWeb.Schemas.GuestInvitationKeyVersionContext,
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      invited_email: %Schema{type: :string, format: :email, nullable: true},
      delivery_mode: %Schema{type: :string, enum: ["unknown_fragment", "known_recipient"]},
      recipient_user_id: %Schema{type: :string, format: :uuid, nullable: true},
      recipient_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      },
      invited_by: %Schema{type: :string, format: :uuid},
      kek_version: %Schema{type: :integer, minimum: 1, nullable: true},
      bootstrap_key_commitment: %Schema{type: :string},
      encrypted_bootstrap_package: RefMDWeb.Schemas.GuestInvitationBootstrapPackage,
      bootstrap_package_hash: %Schema{type: :string},
      bootstrap_package_key_recipient_wrap: RefMDWeb.Schemas.InvitationPackageKeyRecipientWrap,
      bootstrap_package_key_maintenance_wrap: RefMDWeb.Schemas.InvitationBootstrapMaintenanceWrap,
      bootstrap_suite_id: %Schema{
        type: :string,
        enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]
      },
      capability_context_hash: %Schema{type: :string},
      max_redemptions: %Schema{type: :integer, nullable: true},
      redemption_count: %Schema{type: :integer},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      revoked_at: %Schema{type: :string, format: :"date-time", nullable: true}
    },
    required: [
      :invitation_id,
      :workspace_id,
      :token_prefix,
      :scope_kind,
      :key_version_context,
      :permission,
      :delivery_mode,
      :recipient_device_ids,
      :invited_by,
      :kek_version,
      :bootstrap_key_commitment,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :bootstrap_package_key_recipient_wrap,
      :bootstrap_package_key_maintenance_wrap,
      :bootstrap_suite_id,
      :capability_context_hash,
      :redemption_count,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.GuestInvitationsListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GuestInvitationsListResponse",
    type: :object,
    properties: %{
      invitations: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.GuestInvitationResponse
      }
    },
    required: [:invitations]
  })
end

defmodule RefMDWeb.Schemas.RedeemGuestInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RedeemGuestInvitationRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      token: %Schema{type: :string},
      guest_user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      device_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
      device_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      identity_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial,
      identity_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      recoverable_identity_secret_record: RefMDWeb.Schemas.RecoverableIdentitySecretRecord,
      client_nonce: %Schema{type: :string},
      user_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      device_name: %Schema{type: :string, nullable: true},
      device_type: %Schema{type: :string, nullable: true}
    },
    required: [
      :token,
      :guest_user_id,
      :device_id,
      :device_hybrid_encryption_public_key_material,
      :device_hybrid_signing_public_key_material,
      :identity_hybrid_encryption_public_key_material,
      :identity_hybrid_signing_public_key_material,
      :recoverable_identity_secret_record,
      :client_nonce,
      :user_key_directory_events,
      :user_key_directory_checkpoint,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.RedeemGuestInvitationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RedeemGuestInvitationResponse",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_name: %Schema{type: :string},
      invitation_id: %Schema{type: :string, format: :uuid},
      scope_kind: %Schema{type: :string, enum: ["workspace", "document", "folder", "share"]},
      scope_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_scope_kind: %Schema{
        type: :string,
        enum: ["document", "folder"],
        nullable: true
      },
      share_scope_id: %Schema{type: :string, format: :uuid, nullable: true},
      key_version_context: RefMDWeb.Schemas.GuestInvitationKeyVersionContext,
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      guest_user_id: %Schema{type: :string, format: :uuid},
      guest_device_id: %Schema{type: :string, format: :uuid},
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      user_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      recipient_delivery_artifacts: %Schema{
        allOf: [RefMDWeb.Schemas.ApproveInvitationDeliveryAttemptRequest],
        nullable: true
      }
    },
    required: [
      :workspace_id,
      :workspace_name,
      :invitation_id,
      :scope_kind,
      :share_id,
      :share_scope_kind,
      :share_scope_id,
      :key_version_context,
      :permission,
      :guest_user_id,
      :guest_device_id,
      :user_key_directory_checkpoint,
      :user_key_directory_events
    ]
  })
end
