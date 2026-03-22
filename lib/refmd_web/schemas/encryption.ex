defmodule RefMDWeb.Schemas.DistributeUmkRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DistributeUmkRequest",
    type: :object,
    properties: %{
      sender_device_id: %Schema{type: :string, format: :uuid},
      encrypted_umk: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:sender_device_id, :encrypted_umk, :nonce]
  })
end

defmodule RefMDWeb.Schemas.GetUmkResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "GetUmkResponse",
    type: :object,
    properties: %{
      encrypted_umk: %Schema{type: :string},
      nonce: %Schema{type: :string},
      sender_device_id: %Schema{type: :string, format: :uuid},
      sender_ecdh_public_key: %Schema{type: :string},
      sender_signing_public_key: %Schema{type: :string}
    },
    required: [
      :encrypted_umk,
      :nonce,
      :sender_device_id,
      :sender_ecdh_public_key,
      :sender_signing_public_key
    ]
  })
end

defmodule RefMDWeb.Schemas.KekRotationStartResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekRotationStartResponse",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      needs_kek_rotation: %Schema{type: :boolean}
    },
    required: [:workspace_id, :needs_kek_rotation]
  })
end

defmodule RefMDWeb.Schemas.KekRotationCompleteRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekRotationCompleteRequest",
    type: :object,
    properties: %{
      new_kek_version: %Schema{type: :integer}
    },
    required: [:new_kek_version]
  })
end

defmodule RefMDWeb.Schemas.MemberEnvelopeItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberEnvelopeItem",
    type: :object,
    properties: %{
      target_user_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer},
      sender_device_id: %Schema{type: :string, format: :uuid},
      encrypted_kek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:target_user_id, :key_version, :sender_device_id, :encrypted_kek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.SaveMemberEnvelopesRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SaveMemberEnvelopesRequest",
    type: :object,
    properties: %{
      envelopes: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.MemberEnvelopeItem}
    },
    required: [:envelopes]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceIdsResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceIdsResponse",
    type: :object,
    properties: %{
      workspace_ids: %Schema{type: :array, items: %Schema{type: :string, format: :uuid}}
    },
    required: [:workspace_ids]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceMemberKeysResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceMemberKeysResponse",
    type: :object,
    properties: %{
      members: %Schema{
        type: :array,
        items: %Schema{
          type: :object,
          properties: %{
            user_id: %Schema{type: :string, format: :uuid},
            ecdh_public_key: %Schema{type: :string},
            signing_public_key: %Schema{type: :string}
          },
          required: [:user_id, :ecdh_public_key, :signing_public_key]
        }
      }
    },
    required: [:members]
  })
end

defmodule RefMDWeb.Schemas.MemberEnvelopeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberEnvelopeResponse",
    type: :object,
    properties: %{
      key_version: %Schema{type: :integer},
      sender_device_id: %Schema{type: :string, format: :uuid},
      sender_user_id: %Schema{type: :string, format: :uuid},
      sender_ecdh_public_key: %Schema{type: :string},
      sender_signing_public_key: %Schema{type: :string},
      encrypted_kek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:key_version, :sender_device_id, :sender_user_id, :encrypted_kek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.CreateWorkspaceKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateWorkspaceKeyRequest",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer},
      sender_device_id: %Schema{type: :string, format: :uuid},
      encrypted_kek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      is_active: %Schema{type: :boolean}
    },
    required: [:device_id, :key_version, :sender_device_id, :encrypted_kek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceKeyItem do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceKeyItem",
    type: :object,
    properties: %{
      key_version: %Schema{type: :integer},
      encrypted_kek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      sender_device_id: %Schema{type: :string, format: :uuid},
      sender_ecdh_public_key: %Schema{type: :string, nullable: true},
      sender_signing_public_key: %Schema{type: :string, nullable: true}
    },
    required: [:key_version, :encrypted_kek, :nonce, :sender_device_id]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceKeysResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceKeysResponse",
    type: :object,
    properties: %{
      current_kek_version: %Schema{type: :integer},
      keys: %Schema{type: :array, items: RefMDWeb.Schemas.WorkspaceKeyItem}
    },
    required: [:current_kek_version, :keys]
  })
end

defmodule RefMDWeb.Schemas.CreateKekBackupRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateKekBackupRequest",
    type: :object,
    properties: %{
      key_version: %Schema{type: :integer},
      encrypted_kek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:key_version, :encrypted_kek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.KekBackupResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekBackupResponse",
    type: :object,
    properties: %{
      key_version: %Schema{type: :integer},
      encrypted_kek: %Schema{type: :string},
      nonce: %Schema{type: :string}
    },
    required: [:key_version, :encrypted_kek, :nonce]
  })
end

defmodule RefMDWeb.Schemas.CreateDocumentKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDocumentKeyRequest",
    type: :object,
    properties: %{
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      key_version: %Schema{type: :integer, minimum: 1},
      kek_version: %Schema{type: :integer, minimum: 1}
    },
    required: [:encrypted_dek, :nonce, :key_version, :kek_version]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeyResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeyResponse",
    type: :object,
    properties: %{
      document_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      is_active: %Schema{type: :boolean},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:document_id, :key_version, :encrypted_dek, :nonce, :is_active, :created_at]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeysResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeysResponse",
    type: :object,
    properties: %{
      keys: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.DocumentKeyResponse
      }
    },
    required: [:keys]
  })
end
