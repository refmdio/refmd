defmodule RefMDWeb.Schemas.InvitationLookupResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationLookupResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      kind: %Schema{type: :string, enum: ["workspace", "guest"]},
      invitation_id: %Schema{type: :string, format: :uuid},
      delivery_mode: %Schema{type: :string, enum: ["unknown_fragment", "known_recipient"]},
      recipient_user_id: %Schema{type: :string, format: :uuid, nullable: true},
      recipient_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      },
      workspace_id: %Schema{type: :string, format: :uuid, nullable: true},
      scope_kind: %Schema{
        type: :string,
        enum: ["workspace", "document", "folder", "share"],
        nullable: true
      },
      scope_id: %Schema{type: :string, format: :uuid, nullable: true},
      share_id: %Schema{type: :string, format: :uuid, nullable: true},
      permission: %Schema{type: :string, enum: ["view", "edit"], nullable: true},
      kek_version: %Schema{type: :integer, nullable: true},
      key_version_context: %Schema{
        allOf: [RefMDWeb.Schemas.GuestInvitationKeyVersionContext],
        nullable: true
      },
      encrypted_bootstrap_package: %Schema{
        oneOf: [
          RefMDWeb.Schemas.WorkspaceInvitationBootstrapPackage,
          RefMDWeb.Schemas.GuestInvitationBootstrapPackage
        ]
      },
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope]
      },
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
      :kind,
      :invitation_id,
      :delivery_mode,
      :recipient_user_id,
      :recipient_device_ids,
      :kek_version,
      :share_id,
      :key_version_context,
      :encrypted_bootstrap_package,
      :workspace_key_directory_checkpoint,
      :workspace_key_directory_checkpoint_ancestry,
      :workspace_key_directory_event_ancestry
    ],
    oneOf: [
      %Schema{
        properties: %{
          delivery_mode: %Schema{type: :string, enum: ["unknown_fragment"]},
          recipient_user_id: %Schema{type: :string, nullable: true, enum: [nil]},
          recipient_device_ids: %Schema{
            type: :array,
            maxItems: 0,
            items: %Schema{type: :string, format: :uuid}
          }
        },
        required: [:delivery_mode, :recipient_user_id, :recipient_device_ids]
      },
      %Schema{
        properties: %{
          delivery_mode: %Schema{type: :string, enum: ["known_recipient"]},
          recipient_user_id: %Schema{type: :string, format: :uuid},
          recipient_device_ids: %Schema{
            type: :array,
            minItems: 1,
            items: %Schema{type: :string, format: :uuid}
          }
        },
        required: [:delivery_mode, :recipient_user_id, :recipient_device_ids]
      }
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationRecipientDevice do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationRecipientDevice",
    type: :object,
    additionalProperties: false,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      encryption_key_id: %Schema{type: :string},
      hybrid_encryption_public_key_material: RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      signing_key_id: %Schema{type: :string},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: %Schema{type: :string}
    },
    required: [
      :device_id,
      :encryption_key_id,
      :hybrid_encryption_public_key_material,
      :signing_key_id,
      :hybrid_signing_public_key_material,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.UnknownInvitationRecipientResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UnknownInvitationRecipientResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      delivery_mode: %Schema{type: :string, enum: ["unknown_fragment"]},
      recipient_user_id: %Schema{type: :string, nullable: true, enum: [nil]},
      devices: %Schema{
        type: :array,
        maxItems: 0,
        items: RefMDWeb.Schemas.InvitationRecipientDevice
      }
    },
    required: [:delivery_mode, :recipient_user_id, :devices]
  })
end

defmodule RefMDWeb.Schemas.KnownInvitationRecipientResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KnownInvitationRecipientResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      delivery_mode: %Schema{type: :string, enum: ["known_recipient"]},
      recipient_user_id: %Schema{type: :string, format: :uuid},
      devices: %Schema{
        type: :array,
        minItems: 1,
        items: RefMDWeb.Schemas.InvitationRecipientDevice
      }
    },
    required: [:delivery_mode, :recipient_user_id, :devices]
  })
end

defmodule RefMDWeb.Schemas.InvitationRecipientResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationRecipientResponse",
    oneOf: [
      RefMDWeb.Schemas.UnknownInvitationRecipientResponse,
      RefMDWeb.Schemas.KnownInvitationRecipientResponse
    ]
  })
end
