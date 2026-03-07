defmodule RefMDWeb.Schemas do
  alias OpenApiSpex.Schema

  # ── Common ──────────────────────────────────────

  defmodule KdfParams do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "KdfParams",
      type: :object,
      properties: %{
        algorithm: %Schema{type: :string},
        memory: %Schema{type: :integer},
        iterations: %Schema{type: :integer},
        parallelism: %Schema{type: :integer},
        hash_length: %Schema{type: :integer}
      },
      required: [:algorithm, :memory, :iterations, :parallelism, :hash_length]
    })
  end

  defmodule UserInfo do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "UserInfo",
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :uuid},
        email: %Schema{type: :string, format: :email},
        name: %Schema{type: :string}
      },
      required: [:id, :email, :name]
    })
  end

  defmodule UserInfoWithSetup do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "UserInfoWithSetup",
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :uuid},
        email: %Schema{type: :string, format: :email},
        name: %Schema{type: :string},
        encryption_setup_at: %Schema{type: :string, format: :"date-time", nullable: true}
      },
      required: [:id, :email, :name]
    })
  end

  defmodule OkResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "OkResponse",
      type: :object,
      properties: %{
        ok: %Schema{type: :boolean}
      },
      required: [:ok]
    })
  end

  defmodule ErrorResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ErrorResponse",
      type: :object,
      properties: %{
        error: %Schema{type: :string},
        step: %Schema{type: :string},
        details: %Schema{type: :object, additionalProperties: true}
      },
      required: [:error]
    })
  end

  # ── Auth Schemas ────────────────────────────────

  defmodule SaltResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "SaltResponse",
      type: :object,
      properties: %{
        salt: %Schema{type: :string},
        kdf_params: KdfParams
      },
      required: [:salt, :kdf_params]
    })
  end

  defmodule RegisterRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RegisterRequest",
      type: :object,
      properties: %{
        email: %Schema{type: :string, format: :email},
        name: %Schema{type: :string},
        auth_key: %Schema{type: :string},
        salt: %Schema{type: :string},
        encrypted_umk: %Schema{type: :string},
        umk_nonce: %Schema{type: :string},
        kdf_params: KdfParams,
        recovery_encrypted_umk: %Schema{type: :string},
        recovery_nonce: %Schema{type: :string},
        ecdh_public_key: %Schema{type: :string},
        signing_public_key: %Schema{type: :string},
        encrypted_ecdh_private: %Schema{type: :string},
        encrypted_ecdh_private_nonce: %Schema{type: :string},
        encrypted_signing_private: %Schema{type: :string},
        encrypted_signing_private_nonce: %Schema{type: :string}
      },
      required: [
        :email, :name, :auth_key, :salt, :encrypted_umk, :umk_nonce,
        :kdf_params, :recovery_encrypted_umk, :recovery_nonce,
        :ecdh_public_key, :signing_public_key,
        :encrypted_ecdh_private, :encrypted_ecdh_private_nonce,
        :encrypted_signing_private, :encrypted_signing_private_nonce
      ]
    })
  end

  defmodule RegisterResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RegisterResponse",
      type: :object,
      properties: %{
        user: UserInfo,
        workspace_id: %Schema{type: :string, format: :uuid},
        session_id: %Schema{type: :string, format: :uuid}
      },
      required: [:user, :workspace_id, :session_id]
    })
  end

  defmodule LoginRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "LoginRequest",
      type: :object,
      properties: %{
        email: %Schema{type: :string, format: :email},
        auth_key: %Schema{type: :string},
        device_id: %Schema{type: :string, format: :uuid},
        remember_me: %Schema{type: :boolean}
      },
      required: [:email, :auth_key]
    })
  end

  defmodule LoginKeys do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "LoginKeys",
      type: :object,
      nullable: true,
      properties: %{
        encrypted_umk: %Schema{type: :string},
        umk_nonce: %Schema{type: :string},
        encrypted_ecdh_private: %Schema{type: :string},
        encrypted_ecdh_private_nonce: %Schema{type: :string},
        encrypted_signing_private: %Schema{type: :string},
        encrypted_signing_private_nonce: %Schema{type: :string}
      },
      required: [
        :encrypted_ecdh_private, :encrypted_ecdh_private_nonce,
        :encrypted_signing_private, :encrypted_signing_private_nonce
      ]
    })
  end

  defmodule LoginResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "LoginResponse",
      type: :object,
      properties: %{
        user: UserInfo,
        session_id: %Schema{type: :string, format: :uuid},
        device_verified: %Schema{type: :boolean},
        keys: LoginKeys,
        kdf_migration_required: %Schema{type: :boolean},
        target_kdf_params: KdfParams
      },
      required: [:user, :session_id, :device_verified]
    })
  end

  defmodule MeResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "MeResponse",
      type: :object,
      properties: %{
        user: UserInfoWithSetup,
        session_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid, nullable: true},
        device_verified: %Schema{type: :boolean},
        expires_at: %Schema{type: :string, format: :"date-time"},
        auth_type: %Schema{type: :string, nullable: true},
        keys: LoginKeys
      },
      required: [:user, :session_id, :device_verified, :expires_at]
    })
  end

  defmodule KdfMigrationRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "KdfMigrationRequest",
      type: :object,
      properties: %{
        new_auth_key: %Schema{type: :string},
        new_encrypted_umk: %Schema{type: :string},
        new_nonce: %Schema{type: :string},
        new_kdf_params: KdfParams
      },
      required: [:new_auth_key, :new_encrypted_umk, :new_nonce, :new_kdf_params]
    })
  end

  # ── Device Schemas ──────────────────────────────

  defmodule CreatePendingDeviceRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CreatePendingDeviceRequest",
      type: :object,
      properties: %{
        name: %Schema{type: :string},
        device_type: %Schema{type: :string},
        ecdh_public_key: %Schema{type: :string},
        signing_public_key: %Schema{type: :string},
        client_nonce: %Schema{type: :string}
      },
      required: [:name, :device_type, :ecdh_public_key, :signing_public_key, :client_nonce]
    })
  end

  defmodule CreatePendingDeviceResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CreatePendingDeviceResponse",
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :uuid}
      },
      required: [:id]
    })
  end

  defmodule ApproveDeviceRequest do
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

  defmodule DeviceInfo do
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

  defmodule ApproveDeviceResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ApproveDeviceResponse",
      type: :object,
      properties: %{
        device: DeviceInfo
      },
      required: [:device]
    })
  end

  # ── Encryption Schemas ──────────────────────────

  defmodule CreateWorkspaceKeyRequest do
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

  defmodule WorkspaceKeyItem do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "WorkspaceKeyItem",
      type: :object,
      properties: %{
        key_version: %Schema{type: :integer},
        encrypted_kek: %Schema{type: :string},
        nonce: %Schema{type: :string},
        sender_device_id: %Schema{type: :string, format: :uuid}
      },
      required: [:key_version, :encrypted_kek, :nonce, :sender_device_id]
    })
  end

  defmodule WorkspaceKeysResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "WorkspaceKeysResponse",
      type: :object,
      properties: %{
        keys: %Schema{type: :array, items: WorkspaceKeyItem}
      },
      required: [:keys]
    })
  end

  defmodule CreateKekBackupRequest do
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

  defmodule KekBackupResponse do
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
end
