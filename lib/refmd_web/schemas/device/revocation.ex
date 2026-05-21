defmodule RefMDWeb.Schemas.RevokeDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RevokeDeviceRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      revocation_mode: %Schema{type: :string, enum: ["security", "retire"]},
      revocation_signature: RefMDWeb.Schemas.HybridSignature,
      revoked_at: %Schema{type: :integer, description: "Unix timestamp in milliseconds"},
      user_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      workspace_key_directory_appends: %Schema{
        type: :array,
        items: %Schema{
          type: :object,
          additionalProperties: false,
          properties: %{
            workspace_id: %Schema{type: :string, format: :uuid},
            events: %Schema{
              type: :array,
              items: RefMDWeb.Schemas.KeyDirectoryEnvelope
            },
            checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          required: [:workspace_id, :events, :checkpoint]
        }
      }
    },
    required: [
      :revocation_signature,
      :revoked_at,
      :user_key_directory_events,
      :user_key_directory_checkpoint,
      :workspace_key_directory_appends
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceRotationInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceRotationInfo",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      current_kek_version: %Schema{type: :integer}
    },
    required: [:workspace_id, :current_kek_version]
  })
end

defmodule RefMDWeb.Schemas.RemoveMemberResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RemoveMemberResponse",
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

defmodule RefMDWeb.Schemas.RevokeDeviceResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RevokeDeviceResponse",
    type: :object,
    properties: %{
      revoked_device_id: %Schema{type: :string, format: :uuid},
      revocation_mode: %Schema{type: :string},
      workspaces_needing_kek_rotation: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.WorkspaceRotationInfo
      }
    },
    required: [:revoked_device_id, :revocation_mode, :workspaces_needing_kek_rotation]
  })
end
