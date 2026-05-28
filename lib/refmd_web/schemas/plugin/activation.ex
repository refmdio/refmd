defmodule RefMDWeb.Schemas.PluginActivationUpdateRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginActivationUpdateRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      enabled: %OpenApiSpex.Schema{type: :boolean}
    }
  })
end
