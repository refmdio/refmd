defmodule RefMDWeb.Schemas.ApproveDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base_properties %{
    approval_signature: RefMDWeb.Schemas.HybridSignature,
    approval_proof: RefMDWeb.Schemas.DeviceApprovalProof,
    user_key_directory_events: %Schema{
      type: :array,
      items: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
    workspace_key_directory_appends: %Schema{
      type: :array,
      items: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          workspace_id: %Schema{type: :string, format: :uuid},
          events: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.KeyDirectoryEnvelope
          },
          checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
        },
        required: [:workspace_id, :events, :checkpoint]
      }
    }
  }

  @base_required [
    :approval_signature_surface,
    :approval_signature,
    :approval_proof,
    :user_key_directory_events,
    :user_key_directory_checkpoint,
    :workspace_key_directory_appends
  ]

  @device_approval_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties:
      Map.merge(@base_properties, %{
        approval_signature_surface: %Schema{type: :string, enum: ["device_approval"]},
        initial_ake_offers: RefMDWeb.Schemas.InitialAkeOfferBundle
      }),
    required: @base_required ++ [:initial_ake_offers]
  }

  @recovery_device_approval_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties:
      Map.merge(@base_properties, %{
        approval_signature_surface: %Schema{type: :string, enum: ["recovery_device_approval"]}
      }),
    required: @base_required
  }

  OpenApiSpex.schema(%{
    title: "ApproveDeviceRequest",
    oneOf: [@device_approval_schema, @recovery_device_approval_schema]
  })
end

defmodule RefMDWeb.Schemas.ApproveDeviceResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ApproveDeviceResponse",
    type: :object,
    properties: %{
      device: RefMDWeb.Schemas.DeviceFullInfo
    },
    required: [:device]
  })
end
