defmodule RefMDWeb.Schemas.PasswordSetResponse do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.PasswordSetRequest do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.ChangePasswordRequest do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.RegenerateRecoveryKeyRequest do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.PasswordResetRequestBody do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.PasswordResetVerifyBody do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.PasswordResetVerifyResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PasswordResetVerifyResponse",
    type: :object,
    properties: %{
      user: RefMDWeb.Schemas.UserInfo,
      session_id: %Schema{type: :string, format: :uuid}
    },
    required: [:user, :session_id]
  })
end

defmodule RefMDWeb.Schemas.RecoveryDataResponse do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.RecoveryChallengeRequest do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.RecoveryChallengeResponse do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.RecoverySessionRequest do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.RecoverySessionResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecoverySessionResponse",
    type: :object,
    properties: %{
      user: RefMDWeb.Schemas.UserInfo,
      session_id: %Schema{type: :string, format: :uuid},
      is_recovery: %Schema{type: :boolean}
    },
    required: [:user, :session_id, :is_recovery]
  })
end
