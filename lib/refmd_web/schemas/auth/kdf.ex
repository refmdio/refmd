defmodule RefMDWeb.Schemas.KdfMigrationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KdfMigrationRequest",
    type: :object,
    properties: %{
      new_auth_key: %Schema{type: :string},
      new_encrypted_umk: %Schema{type: :string},
      new_nonce: %Schema{type: :string},
      new_kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:new_auth_key, :new_encrypted_umk, :new_nonce, :new_kdf_params]
  })
end
