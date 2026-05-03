defmodule RefMDWeb.Schemas.CreateInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateInvitationRequest",
    type: :object,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      token_hash: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      encrypted_kek: %Schema{type: :string},
      kek_nonce: %Schema{type: :string},
      kek_version: %Schema{type: :integer},
      role_id: %Schema{type: :string, format: :uuid, nullable: true},
      invited_email: %Schema{type: :string, format: :email},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true}
    },
    required: [
      :invitation_id,
      :token_hash,
      :token_prefix,
      :encrypted_kek,
      :kek_nonce,
      :kek_version,
      :invited_email
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationResponse",
    type: :object,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      token_prefix: %Schema{type: :string},
      role_id: %Schema{type: :string, format: :uuid, nullable: true},
      invited_email: %Schema{type: :string, format: :email},
      kek_version: %Schema{type: :integer},
      is_used: %Schema{type: :boolean},
      expires_at: %Schema{type: :string, format: :"date-time"},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :invitation_id,
      :workspace_id,
      :token_prefix,
      :invited_email,
      :kek_version,
      :is_used,
      :expires_at,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationListItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationListItem",
    type: :object,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      token_prefix: %Schema{type: :string},
      role_id: %Schema{type: :string, format: :uuid},
      role_name: %Schema{type: :string},
      invited_by: %Schema{type: :string, format: :uuid},
      invited_email: %Schema{type: :string, format: :email},
      kek_version: %Schema{type: :integer},
      is_used: %Schema{type: :boolean},
      expires_at: %Schema{type: :string, format: :"date-time"},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :invitation_id,
      :workspace_id,
      :token_prefix,
      :invited_by,
      :invited_email,
      :kek_version,
      :is_used,
      :expires_at,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationsListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationsListResponse",
    type: :object,
    properties: %{
      invitations: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.InvitationListItem}
    },
    required: [:invitations]
  })
end

defmodule RefMDWeb.Schemas.AcceptInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AcceptInvitationRequest",
    type: :object,
    properties: %{
      token: %Schema{type: :string}
    },
    required: [:token]
  })
end

defmodule RefMDWeb.Schemas.InvitationLookupRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationLookupRequest",
    type: :object,
    properties: %{
      token: %Schema{type: :string}
    },
    required: [:token]
  })
end

defmodule RefMDWeb.Schemas.InvitationLookupResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationLookupResponse",
    type: :object,
    properties: %{
      kind: %Schema{type: :string, enum: ["member", "guest"]}
    },
    required: [:kind]
  })
end

defmodule RefMDWeb.Schemas.AcceptInvitationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AcceptInvitationResponse",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_name: %Schema{type: :string},
      role_name: %Schema{type: :string, nullable: true},
      invitation_id: %Schema{type: :string, format: :uuid},
      encrypted_kek: %Schema{type: :string},
      kek_nonce: %Schema{type: :string},
      kek_version: %Schema{type: :integer}
    },
    required: [
      :workspace_id,
      :workspace_name,
      :invitation_id,
      :encrypted_kek,
      :kek_nonce,
      :kek_version
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateGuestInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateGuestInvitationRequest",
    type: :object,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      token_hash: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      target_scope: %Schema{type: :string, enum: ["workspace", "document", "folder"]},
      target_document_id: %Schema{type: :string, format: :uuid, nullable: true},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      encrypted_kek: %Schema{type: :string},
      kek_nonce: %Schema{type: :string},
      kek_version: %Schema{type: :integer},
      max_redemptions: %Schema{type: :integer, nullable: true},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true}
    },
    required: [
      :invitation_id,
      :token_hash,
      :token_prefix,
      :target_scope,
      :permission,
      :encrypted_kek,
      :kek_nonce,
      :kek_version
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
      target_scope: %Schema{type: :string},
      target_document_id: %Schema{type: :string, format: :uuid, nullable: true},
      permission: %Schema{type: :string},
      invited_by: %Schema{type: :string, format: :uuid},
      kek_version: %Schema{type: :integer},
      max_redemptions: %Schema{type: :integer},
      redemption_count: %Schema{type: :integer},
      expires_at: %Schema{type: :string, format: :"date-time"},
      created_at: %Schema{type: :string, format: :"date-time"},
      revoked_at: %Schema{type: :string, format: :"date-time", nullable: true}
    },
    required: [
      :invitation_id,
      :workspace_id,
      :token_prefix,
      :target_scope,
      :permission,
      :invited_by,
      :kek_version,
      :max_redemptions,
      :redemption_count,
      :expires_at,
      :created_at,
      :revoked_at
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
    properties: %{
      token: %Schema{type: :string},
      guest_user_id: %Schema{type: :string, format: :uuid},
      device_signing_pub_key: %Schema{type: :string},
      device_encryption_pub_key: %Schema{type: :string},
      identity_signing_pub_key: %Schema{type: :string},
      identity_encryption_pub_key: %Schema{type: :string},
      identity_signature: %Schema{type: :string},
      client_nonce: %Schema{type: :string},
      recovery_encrypted_umk: %Schema{type: :string},
      recovery_nonce: %Schema{type: :string},
      encrypted_identity_encryption_private: %Schema{type: :string},
      encrypted_identity_encryption_private_nonce: %Schema{type: :string},
      encrypted_identity_signing_private: %Schema{type: :string},
      encrypted_identity_signing_private_nonce: %Schema{type: :string},
      device_name: %Schema{type: :string, nullable: true},
      device_type: %Schema{type: :string, nullable: true}
    },
    required: [
      :token,
      :guest_user_id,
      :device_signing_pub_key,
      :device_encryption_pub_key,
      :identity_signing_pub_key,
      :identity_encryption_pub_key,
      :identity_signature,
      :client_nonce,
      :recovery_encrypted_umk,
      :recovery_nonce,
      :encrypted_identity_encryption_private,
      :encrypted_identity_encryption_private_nonce,
      :encrypted_identity_signing_private,
      :encrypted_identity_signing_private_nonce
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
      target_scope: %Schema{type: :string},
      target_document_id: %Schema{type: :string, format: :uuid, nullable: true},
      permission: %Schema{type: :string},
      guest_user_id: %Schema{type: :string, format: :uuid},
      guest_device_id: %Schema{type: :string, format: :uuid},
      encrypted_kek: %Schema{type: :string},
      kek_nonce: %Schema{type: :string},
      kek_version: %Schema{type: :integer}
    },
    required: [
      :workspace_id,
      :workspace_name,
      :invitation_id,
      :target_scope,
      :permission,
      :guest_user_id,
      :guest_device_id,
      :encrypted_kek,
      :kek_nonce,
      :kek_version
    ]
  })
end
