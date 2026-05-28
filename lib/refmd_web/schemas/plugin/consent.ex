defmodule RefMDWeb.Schemas.PluginConsentEventRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginConsentEventRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      plugin_id: %Schema{type: :string, minLength: 1},
      package_id: %Schema{type: :string, format: :uuid},
      application_id: %Schema{type: :string, format: :uuid},
      activation_id: %Schema{type: :string, format: :uuid},
      owner_scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      application_scope_kind: %Schema{type: :string, enum: ["workspace"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      version: %Schema{type: :string, minLength: 1},
      bundle_hash: %Schema{type: :string, minLength: 1},
      manifest_hash: %Schema{type: :string, minLength: 1},
      resource_manifest_hash: %Schema{type: :string, minLength: 1},
      permissions_hash: %Schema{type: :string, minLength: 1},
      endpoint_hash: %Schema{type: :string, minLength: 1},
      document_scope_hash: %Schema{type: :string, minLength: 1},
      signer_user_id: %Schema{type: :string, format: :uuid},
      signer_device_id: %Schema{type: :string, format: :uuid},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      decision: %Schema{type: :string, enum: ["allow", "deny", "revoke"]},
      consent_epoch: %Schema{type: :integer, minimum: 1},
      previous_event_hash: %Schema{type: :string, nullable: true},
      event_hash: %Schema{type: :string, minLength: 1},
      hybrid_signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [
      :plugin_id,
      :package_id,
      :application_id,
      :activation_id,
      :owner_scope_kind,
      :application_scope_kind,
      :workspace_id,
      :version,
      :bundle_hash,
      :manifest_hash,
      :resource_manifest_hash,
      :permissions_hash,
      :endpoint_hash,
      :document_scope_hash,
      :signer_user_id,
      :signer_device_id,
      :decision,
      :consent_epoch,
      :previous_event_hash,
      :event_hash,
      :hybrid_signature
    ]
  })
end
