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
      role_id: %Schema{type: :string, format: :uuid, nullable: true},
      role_name: %Schema{type: :string, nullable: true},
      invited_by: %Schema{type: :string, format: :uuid},
      invited_email: %Schema{type: :string, format: :email},
      kek_version: %Schema{type: :integer},
      is_used: %Schema{type: :boolean},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
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
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationBootstrapCiphertext do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationBootstrapCiphertext",
    type: :object,
    additionalProperties: false,
    properties: %{
      nonce: %Schema{type: :string},
      ciphertext: %Schema{type: :string}
    },
    required: [:nonce, :ciphertext]
  })
end

defmodule RefMDWeb.Schemas.InvitationBootstrapMaintenanceWrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationBootstrapMaintenanceWrap",
    type: :object,
    additionalProperties: false,
    properties: %{
      key_version: %Schema{type: :integer, minimum: 1},
      nonce: %Schema{type: :string},
      ciphertext: %Schema{type: :string}
    },
    required: [:key_version, :nonce, :ciphertext]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceInvitationBootstrapAad do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceInvitationBootstrapAad",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.workspace-invitation-bootstrap"]},
      version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      invitation_id: %Schema{type: :string, format: :uuid},
      role_id: %Schema{type: :string, format: :uuid},
      invited_email: %Schema{type: :string, format: :email},
      key_version_context: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{workspace_kek_version: %Schema{type: :integer, minimum: 1}},
        required: [:workspace_kek_version]
      },
      token_hash: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :suite_id,
      :workspace_id,
      :invitation_id,
      :role_id,
      :invited_email,
      :key_version_context,
      :token_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceInvitationBootstrapPackage do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceInvitationBootstrapPackage",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.workspace-invitation-bootstrap"]},
      version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer, minimum: 1},
      aad: RefMDWeb.Schemas.WorkspaceInvitationBootstrapAad,
      encrypted_payload: RefMDWeb.Schemas.InvitationBootstrapCiphertext,
      package_key_recipient_wrap: RefMDWeb.Schemas.InvitationBootstrapCiphertext,
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

defmodule RefMDWeb.Schemas.CreateInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateInvitationRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      token_hash: %Schema{type: :string},
      token_prefix: %Schema{type: :string},
      kek_version: %Schema{type: :integer},
      role_id: %Schema{type: :string, format: :uuid, nullable: true},
      invited_email: %Schema{type: :string, format: :email},
      expires_at: %Schema{type: :string, format: :"date-time", nullable: true},
      bootstrap_key_commitment: %Schema{type: :string},
      encrypted_bootstrap_package: RefMDWeb.Schemas.WorkspaceInvitationBootstrapPackage,
      bootstrap_package_hash: %Schema{type: :string},
      bootstrap_package_key_recipient_wrap: RefMDWeb.Schemas.InvitationBootstrapCiphertext,
      bootstrap_package_key_maintenance_wrap: RefMDWeb.Schemas.InvitationBootstrapMaintenanceWrap,
      bootstrap_suite_id: %Schema{
        type: :string,
        enum: ["refmd-v2-invitation-bootstrap-xchacha20poly1305"]
      },
      capability_context_hash: %Schema{type: :string},
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
      :kek_version,
      :invited_email,
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

defmodule RefMDWeb.Schemas.InvitationResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationResponse",
    allOf: [RefMDWeb.Schemas.InvitationListItem]
  })
end

defmodule RefMDWeb.Schemas.RevokeInvitationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RevokeInvitationRequest",
    type: :object,
    properties: %{
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [:workspace_key_directory_events, :workspace_key_directory_checkpoint]
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
      token: %Schema{type: :string},
      member_envelope: RefMDWeb.Schemas.MemberEnvelopeItem,
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :token,
      :member_envelope,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.AcceptInvitationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "AcceptInvitationResponse",
    type: :object,
    properties: %{
      status: %Schema{type: :string, enum: ["accepted"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_name: %Schema{type: :string},
      role_name: %Schema{type: :string},
      invitation_id: %Schema{type: :string, format: :uuid},
      kek_version: %Schema{type: :integer},
      encrypted_bootstrap_package: %Schema{
        allOf: [RefMDWeb.Schemas.WorkspaceInvitationBootstrapPackage],
        nullable: true
      },
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      }
    },
    required: [
      :status,
      :workspace_id,
      :workspace_name,
      :role_name,
      :invitation_id,
      :kek_version
    ]
  })
end
