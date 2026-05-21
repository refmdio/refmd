defmodule RefMDWeb.Schemas.VerifyKeyRequest do
  alias OpenApiSpex.Schema
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

defmodule RefMDWeb.Schemas.SaltResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SaltResponse",
    type: :object,
    properties: %{
      salt: %Schema{type: :string},
      kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:salt, :kdf_params]
  })
end
