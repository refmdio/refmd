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
