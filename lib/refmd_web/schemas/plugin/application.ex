defmodule RefMDWeb.Schemas.PluginApplicationApplyRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginApplicationApplyRequest",
    type: :object,
    required: [:package_id],
    additionalProperties: false,
    properties: %{
      package_id: %OpenApiSpex.Schema{type: :string, format: :uuid}
    }
  })
end

defmodule RefMDWeb.Schemas.PluginApplicationUpdateRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginApplicationUpdateRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      enabled: %OpenApiSpex.Schema{type: :boolean},
      workspace_policy_result: %OpenApiSpex.Schema{
        type: :string,
        enum: ["allowed", "denied", "needs_admin_review"]
      }
    }
  })
end
