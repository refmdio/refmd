defmodule RefMDWeb.Schemas.PluginNetworkProxyRegistration do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginNetworkProxyRegistration",
    type: :object,
    nullable: true,
    properties: %{
      id: %Schema{type: :string},
      label: %Schema{type: :string},
      base_url: %Schema{type: :string},
      scope: %Schema{type: :string, enum: ["user", "workspace"]},
      enabled: %Schema{type: :boolean},
      operator_label: %Schema{type: :string},
      allowed_workspace_ids: %Schema{type: :array, items: %Schema{type: :string}},
      allowed_user_ids: %Schema{type: :array, items: %Schema{type: :string}},
      verification_material: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          response_signing_key: %Schema{type: :string},
          response_signature_protocol: %Schema{type: :string},
          response_key_id: %Schema{type: :string}
        }
      },
      revoked: %Schema{type: :boolean},
      policy: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          max_request_size: %Schema{type: :integer, minimum: 1},
          max_response_size: %Schema{type: :integer, minimum: 1},
          allowed_route_classes: %Schema{type: :array, items: %Schema{type: :string}},
          allowed_endpoint_ids: %Schema{type: :array, items: %Schema{type: :string}},
          denied_endpoint_ids: %Schema{type: :array, items: %Schema{type: :string}}
        }
      }
    },
    required: [:id, :label, :base_url, :scope, :enabled]
  })
end
