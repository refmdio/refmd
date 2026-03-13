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
        details: %Schema{type: :object, additionalProperties: true}
      },
      required: [:error]
    })
  end

  # ── Auth Schemas ────────────────────────────────

  defmodule VerifyKeyRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "VerifyKeyRequest",
      type: :object,
      properties: %{
        auth_key: %Schema{type: :string}
      },
      required: [:auth_key]
    })
  end

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
        user_id: %Schema{
          type: :string,
          format: :uuid,
          description: "Client-generated UUID for AAD binding"
        },
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
        :user_id,
        :email,
        :name,
        :auth_key,
        :salt,
        :encrypted_umk,
        :umk_nonce,
        :kdf_params,
        :recovery_encrypted_umk,
        :recovery_nonce,
        :ecdh_public_key,
        :signing_public_key,
        :encrypted_ecdh_private,
        :encrypted_ecdh_private_nonce,
        :encrypted_signing_private,
        :encrypted_signing_private_nonce
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
        :encrypted_ecdh_private,
        :encrypted_ecdh_private_nonce,
        :encrypted_signing_private,
        :encrypted_signing_private_nonce
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
        target_kdf_params: KdfParams,
        encrypted_umk: %Schema{type: :string},
        umk_nonce: %Schema{type: :string}
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
        user_id: %Schema{type: :string, format: :uuid},
        email: %Schema{type: :string, format: :email},
        name: %Schema{type: :string},
        encryption_setup_at: %Schema{type: :string, format: :"date-time", nullable: true},
        session_id: %Schema{type: :string, format: :uuid},
        device_id: %Schema{type: :string, format: :uuid, nullable: true},
        device_verified: %Schema{type: :boolean},
        is_recovery: %Schema{type: :boolean},
        expires_at: %Schema{type: :string, format: :"date-time"},
        auth_type: %Schema{type: :string, nullable: true},
        remember_me: %Schema{type: :boolean},
        identity_signing_public_key: %Schema{type: :string, nullable: true},
        keys: LoginKeys
      },
      required: [:user_id, :email, :name, :session_id, :device_verified, :expires_at]
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

  defmodule PopChallengeResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PopChallengeResponse",
      type: :object,
      properties: %{
        challenge: %Schema{type: :string}
      },
      required: [:challenge]
    })
  end

  # ── Password / Recovery Key Schemas ────────────

  defmodule PasswordSetResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PasswordSetResponse",
      type: :object,
      properties: %{
        ok: %Schema{type: :boolean},
        session_id: %Schema{type: :string, format: :uuid}
      },
      required: [:ok, :session_id]
    })
  end

  defmodule PasswordSetRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PasswordSetRequest",
      type: :object,
      properties: %{
        new_auth_key: %Schema{type: :string},
        new_salt: %Schema{type: :string},
        new_encrypted_umk: %Schema{type: :string},
        new_umk_nonce: %Schema{type: :string}
      },
      required: [:new_auth_key, :new_salt, :new_encrypted_umk, :new_umk_nonce]
    })
  end

  defmodule ChangePasswordRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ChangePasswordRequest",
      type: :object,
      properties: %{
        current_auth_key: %Schema{type: :string},
        new_auth_key: %Schema{type: :string},
        new_salt: %Schema{type: :string},
        new_encrypted_umk: %Schema{type: :string},
        new_umk_nonce: %Schema{type: :string}
      },
      required: [:current_auth_key, :new_auth_key, :new_salt, :new_encrypted_umk, :new_umk_nonce]
    })
  end

  defmodule RegenerateRecoveryKeyRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RegenerateRecoveryKeyRequest",
      type: :object,
      properties: %{
        new_recovery_encrypted_umk: %Schema{type: :string},
        new_recovery_nonce: %Schema{type: :string}
      },
      required: [:new_recovery_encrypted_umk, :new_recovery_nonce]
    })
  end

  # ── Password Reset Schemas ────────────────────

  defmodule PasswordResetRequestBody do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PasswordResetRequestBody",
      type: :object,
      properties: %{
        email: %Schema{type: :string, format: :email}
      },
      required: [:email]
    })
  end

  defmodule PasswordResetVerifyBody do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PasswordResetVerifyBody",
      type: :object,
      properties: %{
        token: %Schema{type: :string}
      },
      required: [:token]
    })
  end

  defmodule PasswordResetVerifyResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PasswordResetVerifyResponse",
      type: :object,
      properties: %{
        user: UserInfo,
        session_id: %Schema{type: :string, format: :uuid}
      },
      required: [:user, :session_id]
    })
  end

  # ── Recovery Schemas ──────────────────────────

  defmodule RecoveryDataResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RecoveryDataResponse",
      type: :object,
      properties: %{
        recovery_encrypted_umk: %Schema{type: :string},
        recovery_nonce: %Schema{type: :string},
        encrypted_ecdh_private: %Schema{type: :string},
        encrypted_ecdh_private_nonce: %Schema{type: :string},
        encrypted_signing_private: %Schema{type: :string},
        encrypted_signing_private_nonce: %Schema{type: :string},
        ecdh_public_key: %Schema{type: :string},
        signing_public_key: %Schema{type: :string}
      },
      required: [:recovery_encrypted_umk, :recovery_nonce]
    })
  end

  defmodule RecoveryChallengeRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RecoveryChallengeRequest",
      type: :object,
      properties: %{
        email: %Schema{type: :string, format: :email}
      },
      required: [:email]
    })
  end

  defmodule RecoveryChallengeResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RecoveryChallengeResponse",
      type: :object,
      properties: %{
        challenge: %Schema{type: :string}
      },
      required: [:challenge]
    })
  end

  defmodule RecoverySessionRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RecoverySessionRequest",
      type: :object,
      properties: %{
        email: %Schema{type: :string, format: :email},
        challenge: %Schema{type: :string},
        signature: %Schema{type: :string},
        timestamp: %Schema{type: :integer}
      },
      required: [:email, :challenge, :signature, :timestamp]
    })
  end

  defmodule RecoverySessionResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RecoverySessionResponse",
      type: :object,
      properties: %{
        user: UserInfo,
        session_id: %Schema{type: :string, format: :uuid},
        is_recovery: %Schema{type: :boolean}
      },
      required: [:user, :session_id, :is_recovery]
    })
  end

  # ── Device Schemas ──────────────────────────────

  defmodule BootstrapDeviceRequest do
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

  defmodule CreateDeviceRegistrationRequest do
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

  defmodule CreateDeviceRegistrationResponse do
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

  defmodule DeviceRegistrationInfo do
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

  defmodule DeviceRegistrationsResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "DeviceRegistrationsResponse",
      type: :object,
      properties: %{
        devices: %Schema{type: :array, items: DeviceRegistrationInfo}
      },
      required: [:devices]
    })
  end

  defmodule DeviceRegistrationStatusResponse do
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

  defmodule DeviceFullInfo do
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

  defmodule DevicesResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "DevicesResponse",
      type: :object,
      properties: %{
        devices: %Schema{type: :array, items: DeviceFullInfo}
      },
      required: [:devices]
    })
  end

  # ── Trust Transfer Schemas ─────────────────────

  defmodule TrustTransferNonceRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TrustTransferNonceRequest",
      type: :object,
      properties: %{
        device_id: %Schema{type: :string, format: :uuid}
      },
      required: [:device_id]
    })
  end

  defmodule TrustTransferNonceResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TrustTransferNonceResponse",
      type: :object,
      properties: %{
        nonce: %Schema{type: :string},
        expires_at: %Schema{type: :string, format: :"date-time"}
      },
      required: [:nonce, :expires_at]
    })
  end

  defmodule TrustTransferSendRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TrustTransferSendRequest",
      type: :object,
      properties: %{
        target_device_id: %Schema{type: :string, format: :uuid},
        transfer_nonce: %Schema{type: :string},
        ciphertext: %Schema{type: :string},
        nonce: %Schema{type: :string},
        signature: %Schema{type: :string}
      },
      required: [:target_device_id, :transfer_nonce, :ciphertext, :nonce, :signature]
    })
  end

  defmodule TrustTransferRetrieveRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TrustTransferRetrieveRequest",
      type: :object,
      properties: %{
        device_id: %Schema{type: :string, format: :uuid}
      },
      required: [:device_id]
    })
  end

  defmodule TrustTransferGetResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "TrustTransferGetResponse",
      type: :object,
      properties: %{
        sender_device_id: %Schema{type: :string, format: :uuid},
        sender_ecdh_public_key: %Schema{type: :string},
        sender_signing_public_key: %Schema{type: :string},
        ciphertext: %Schema{type: :string},
        nonce: %Schema{type: :string},
        signature: %Schema{type: :string}
      },
      required: [
        :sender_device_id,
        :sender_ecdh_public_key,
        :sender_signing_public_key,
        :ciphertext,
        :nonce,
        :signature
      ]
    })
  end

  # ── UMK Distribution Schemas ───────────────────

  defmodule DistributeUmkRequest do
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

  defmodule GetUmkResponse do
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

  # ── Device Revocation Schemas ─────────────────

  defmodule RenameDeviceRequest do
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

  defmodule RevokeDeviceRequest do
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

  defmodule WorkspaceRotationInfo do
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

  defmodule RemoveMemberResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RemoveMemberResponse",
      type: :object,
      properties: %{
        ok: %Schema{type: :boolean},
        workspaces_needing_kek_rotation: %Schema{
          type: :array,
          items: WorkspaceRotationInfo
        }
      },
      required: [:ok, :workspaces_needing_kek_rotation]
    })
  end

  defmodule RevokeDeviceResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RevokeDeviceResponse",
      type: :object,
      properties: %{
        revoked_device_id: %Schema{type: :string, format: :uuid},
        revocation_mode: %Schema{type: :string},
        workspaces_needing_kek_rotation: %Schema{
          type: :array,
          items: WorkspaceRotationInfo
        }
      },
      required: [:revoked_device_id, :revocation_mode, :workspaces_needing_kek_rotation]
    })
  end

  # ── KEK Rotation Schemas ─────────────────────

  defmodule KekRotationStartResponse do
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

  defmodule KekRotationCompleteRequest do
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

  defmodule MemberEnvelopeItem do
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

  defmodule SaveMemberEnvelopesRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "SaveMemberEnvelopesRequest",
      type: :object,
      properties: %{
        envelopes: %Schema{type: :array, items: MemberEnvelopeItem}
      },
      required: [:envelopes]
    })
  end

  defmodule WorkspaceIdsResponse do
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

  defmodule WorkspaceMemberKeysResponse do
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
              ecdh_public_key: %Schema{type: :string}
            },
            required: [:user_id, :ecdh_public_key]
          }
        }
      },
      required: [:members]
    })
  end

  defmodule MemberEnvelopeResponse do
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
        sender_device_id: %Schema{type: :string, format: :uuid},
        sender_ecdh_public_key: %Schema{type: :string, nullable: true},
        sender_signing_public_key: %Schema{type: :string, nullable: true}
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
        current_kek_version: %Schema{type: :integer},
        keys: %Schema{type: :array, items: WorkspaceKeyItem}
      },
      required: [:current_kek_version, :keys]
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

  # ── Workspace ──────────────────────────────────

  defmodule WorkspaceResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "WorkspaceResponse",
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :uuid},
        name: %Schema{type: :string},
        slug: %Schema{type: :string},
        description: %Schema{type: :string, nullable: true},
        icon: %Schema{type: :string, nullable: true},
        owner_id: %Schema{type: :string, format: :uuid},
        current_kek_version: %Schema{type: :integer},
        needs_kek_rotation: %Schema{type: :boolean},
        kek_rotation_initiator_user_id: %Schema{type: :string, format: :uuid, nullable: true},
        current_user_role_id: %Schema{type: :string, format: :uuid, nullable: true},
        current_user_base_role: %Schema{type: :string, nullable: true},
        is_default: %Schema{type: :boolean, nullable: true},
        created_at: %Schema{type: :string, format: :"date-time"},
        updated_at: %Schema{type: :string, format: :"date-time"}
      },
      required: [
        :id,
        :name,
        :slug,
        :owner_id,
        :current_kek_version,
        :needs_kek_rotation,
        :created_at,
        :updated_at
      ]
    })
  end

  defmodule WorkspacesListResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "WorkspacesListResponse",
      type: :object,
      properties: %{
        workspaces: %Schema{type: :array, items: WorkspaceResponse}
      },
      required: [:workspaces]
    })
  end

  defmodule CreateWorkspaceRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CreateWorkspaceRequest",
      type: :object,
      properties: %{
        name: %Schema{type: :string, minLength: 1, maxLength: 100},
        description: %Schema{type: :string, maxLength: 500, nullable: true},
        icon: %Schema{type: :string, nullable: true}
      },
      required: [:name]
    })
  end

  defmodule UpdateWorkspaceRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "UpdateWorkspaceRequest",
      type: :object,
      properties: %{
        name: %Schema{type: :string, minLength: 1, maxLength: 100},
        slug: %Schema{type: :string, pattern: "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"},
        description: %Schema{type: :string, maxLength: 500, nullable: true},
        icon: %Schema{type: :string, nullable: true}
      }
    })
  end

  # ── Members ────────────────────────────────────

  defmodule MemberInfo do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "MemberInfo",
      type: :object,
      properties: %{
        user_id: %Schema{type: :string, format: :uuid},
        email: %Schema{type: :string, format: :email},
        name: %Schema{type: :string},
        role_id: %Schema{type: :string, format: :uuid},
        role_name: %Schema{type: :string},
        base_role: %Schema{type: :string, enum: ["owner", "admin", "editor", "viewer"]},
        is_default: %Schema{type: :boolean},
        joined_at: %Schema{type: :string, format: :"date-time"}
      },
      required: [:user_id, :email, :name, :role_id, :role_name, :base_role, :joined_at]
    })
  end

  defmodule MembersListResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "MembersListResponse",
      type: :object,
      properties: %{
        members: %Schema{type: :array, items: MemberInfo}
      },
      required: [:members]
    })
  end

  defmodule MemberDeviceInfo do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "MemberDeviceInfo",
      type: :object,
      properties: %{
        device_id: %Schema{type: :string, format: :uuid},
        signing_public_key: %Schema{type: :string},
        ecdh_public_key: %Schema{type: :string},
        identity_signature: %Schema{type: :string},
        created_at: %Schema{type: :string, format: :"date-time"}
      },
      required: [
        :device_id,
        :signing_public_key,
        :ecdh_public_key,
        :identity_signature,
        :created_at
      ]
    })
  end

  defmodule MemberDevicesResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "MemberDevicesResponse",
      type: :object,
      properties: %{
        devices: %Schema{type: :array, items: MemberDeviceInfo}
      },
      required: [:devices]
    })
  end

  defmodule ChangeMemberRoleRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ChangeMemberRoleRequest",
      type: :object,
      properties: %{
        role_id: %Schema{type: :string, format: :uuid}
      },
      required: [:role_id]
    })
  end

  # ── Roles ──────────────────────────────────────

  defmodule PermissionOverride do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "PermissionOverride",
      type: :object,
      properties: %{
        permission: %Schema{type: :string},
        granted: %Schema{type: :boolean}
      },
      required: [:permission, :granted]
    })
  end

  defmodule RoleResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RoleResponse",
      type: :object,
      properties: %{
        id: %Schema{type: :string, format: :uuid},
        workspace_id: %Schema{type: :string, format: :uuid},
        name: %Schema{type: :string},
        base_role: %Schema{type: :string, enum: ["owner", "admin", "editor", "viewer"]},
        is_default: %Schema{type: :boolean},
        catalog_version: %Schema{type: :integer, nullable: true},
        created_at: %Schema{type: :string, format: :"date-time"},
        permissions: %Schema{type: :array, items: PermissionOverride}
      },
      required: [
        :id,
        :workspace_id,
        :name,
        :base_role,
        :is_default,
        :created_at
      ]
    })
  end

  defmodule RolesListResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RolesListResponse",
      type: :object,
      properties: %{
        roles: %Schema{type: :array, items: RoleResponse}
      },
      required: [:roles]
    })
  end

  defmodule CreateRoleRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "CreateRoleRequest",
      type: :object,
      properties: %{
        name: %Schema{type: :string, minLength: 1, maxLength: 100},
        base_role: %Schema{type: :string, enum: ["admin", "editor", "viewer"]},
        permissions: %Schema{type: :array, items: PermissionOverride}
      },
      required: [:name, :base_role]
    })
  end

  defmodule UpdateRoleRequest do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "UpdateRoleRequest",
      type: :object,
      properties: %{
        name: %Schema{type: :string, minLength: 1, maxLength: 100},
        is_default: %Schema{type: :boolean},
        permissions: %Schema{type: :array, items: PermissionOverride}
      }
    })
  end

  defmodule RoleDeleteResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "RoleDeleteResponse",
      type: :object,
      properties: %{
        ok: %Schema{type: :boolean},
        invalidated_invitation_count: %Schema{type: :integer}
      },
      required: [:ok, :invalidated_invitation_count]
    })
  end

  # ── Invitations ─────────────────────────────────

  defmodule CreateInvitationRequest do
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

  defmodule InvitationResponse do
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

  defmodule InvitationListItem do
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

  defmodule InvitationsListResponse do
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "InvitationsListResponse",
      type: :object,
      properties: %{
        invitations: %Schema{type: :array, items: InvitationListItem}
      },
      required: [:invitations]
    })
  end

  defmodule AcceptInvitationRequest do
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

  defmodule AcceptInvitationResponse do
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
end
