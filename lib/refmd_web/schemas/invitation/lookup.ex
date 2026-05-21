defmodule RefMDWeb.Schemas.InvitationLookupResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationLookupResponse",
    type: :object,
    properties: %{
      kind: %Schema{type: :string, enum: ["workspace", "guest"]},
      invitation_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid, nullable: true},
      scope_kind: %Schema{
        type: :string,
        enum: ["workspace", "document", "folder"],
        nullable: true
      },
      scope_id: %Schema{type: :string, format: :uuid, nullable: true},
      permission: %Schema{type: :string, enum: ["view", "edit"], nullable: true},
      kek_version: %Schema{type: :integer, nullable: true},
      encrypted_bootstrap_package: %Schema{
        oneOf: [
          RefMDWeb.Schemas.WorkspaceInvitationBootstrapPackage,
          RefMDWeb.Schemas.GuestInvitationBootstrapPackage
        ],
        nullable: true
      },
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      }
    },
    required: [:kind]
  })
end
