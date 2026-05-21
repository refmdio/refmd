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
