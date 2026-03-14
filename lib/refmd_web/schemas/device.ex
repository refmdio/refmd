defmodule RefMDWeb.Schemas.BootstrapDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "BootstrapDeviceRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      identity_signing_public_key: %Schema{type: :string},
      device_signing_public_key: %Schema{type: :string},
      device_ecdh_public_key: %Schema{type: :string},
      client_nonce: %Schema{type: :string},
      identity_signature: %Schema{type: :string}
    },
    required: [
      :name,
      :device_type,
      :identity_signing_public_key,
      :device_signing_public_key,
      :device_ecdh_public_key,
      :client_nonce,
      :identity_signature
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateDeviceRegistrationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDeviceRegistrationRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      identity_signing_public_key: %Schema{type: :string},
      device_signing_public_key: %Schema{type: :string},
      device_ecdh_public_key: %Schema{type: :string},
      client_nonce: %Schema{type: :string}
    },
    required: [
      :identity_signing_public_key,
      :device_signing_public_key,
      :device_ecdh_public_key,
      :client_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.CreateDeviceRegistrationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDeviceRegistrationResponse",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      status: %Schema{type: :string}
    },
    required: [:device_id, :status]
  })
end

defmodule RefMDWeb.Schemas.ApproveDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ApproveDeviceRequest",
    type: :object,
    properties: %{
      identity_signature: %Schema{type: :string}
    },
    required: [:identity_signature]
  })
end

defmodule RefMDWeb.Schemas.DeviceInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceInfo",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string}
    },
    required: [:id, :name, :device_type]
  })
end

defmodule RefMDWeb.Schemas.ApproveDeviceResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ApproveDeviceResponse",
    type: :object,
    properties: %{
      device: RefMDWeb.Schemas.DeviceInfo
    },
    required: [:device]
  })
end

defmodule RefMDWeb.Schemas.DeviceRegistrationInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRegistrationInfo",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      ecdh_public_key: %Schema{type: :string},
      signing_public_key: %Schema{type: :string},
      client_nonce: %Schema{type: :string},
      ip_address: %Schema{type: :string, nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      expires_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :id,
      :name,
      :device_type,
      :ecdh_public_key,
      :signing_public_key,
      :client_nonce,
      :created_at,
      :expires_at
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceRegistrationsResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRegistrationsResponse",
    type: :object,
    properties: %{
      devices: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.DeviceRegistrationInfo}
    },
    required: [:devices]
  })
end

defmodule RefMDWeb.Schemas.DeviceRegistrationStatusResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRegistrationStatusResponse",
    type: :object,
    properties: %{
      status: %Schema{type: :string, enum: ["pending", "approved", "expired"]}
    },
    required: [:status]
  })
end

defmodule RefMDWeb.Schemas.DeviceFullInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceFullInfo",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      ecdh_public_key: %Schema{type: :string},
      signing_public_key: %Schema{type: :string},
      client_nonce: %Schema{type: :string},
      identity_signature: %Schema{
        type: :string,
        description: "Identity cross-sign of device keys"
      },
      last_seen_at: %Schema{type: :string, format: :"date-time"},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:id, :name, :device_type, :ecdh_public_key, :signing_public_key]
  })
end

defmodule RefMDWeb.Schemas.DevicesResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DevicesResponse",
    type: :object,
    properties: %{
      devices: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.DeviceFullInfo}
    },
    required: [:devices]
  })
end

defmodule RefMDWeb.Schemas.RenameDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RenameDeviceRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string}
    },
    required: [:name]
  })
end

defmodule RefMDWeb.Schemas.RevokeDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RevokeDeviceRequest",
    type: :object,
    properties: %{
      revocation_mode: %Schema{type: :string, enum: ["security", "retire"]},
      identity_signature: %Schema{type: :string},
      revoked_at: %Schema{type: :integer, description: "Unix timestamp in milliseconds"}
    },
    required: [:identity_signature, :revoked_at]
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
