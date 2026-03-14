defmodule RefMDWeb.Schemas.KdfParams do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.UserInfo do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.UserInfoWithSetup do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.OkResponse do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.ErrorResponse do
  alias OpenApiSpex.Schema
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
