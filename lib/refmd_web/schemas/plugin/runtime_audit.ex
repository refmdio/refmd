defmodule RefMDWeb.Schemas.PluginRuntimeAuditRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @emptyable_string %Schema{type: :string}
  @non_negative_integer %Schema{type: :integer, minimum: 0}
  @string_or_non_negative_integer %Schema{
    anyOf: [@non_negative_integer, %Schema{type: :string}]
  }
  @boolean_or_string %Schema{anyOf: [%Schema{type: :boolean}, %Schema{type: :string}]}
  @runtime_audit_rejected_object %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{nested: %Schema{type: :string}}
  }
  @actor_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      user_id: @emptyable_string,
      device_id: @emptyable_string,
      session_id: @emptyable_string,
      principal_kind: %Schema{
        type: :string,
        enum: ["user", "share_participant", "system", "worker"]
      },
      principal_id: @emptyable_string
    },
    required: [:user_id, :device_id, :session_id, :principal_kind, :principal_id]
  }
  @scope_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      document_id: @emptyable_string,
      share_id: @emptyable_string
    },
    required: [:workspace_id, :document_id, :share_id]
  }
  @resource_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      kind: %Schema{type: :string, enum: ["plugin", "credential", "network_endpoint", "document"]},
      id: %Schema{type: :string},
      version_hash: @emptyable_string
    },
    required: [:kind, :id, :version_hash]
  }
  @action_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      operation: %Schema{type: :string},
      result: %Schema{type: :string, enum: ["allowed", "denied", "failed", "completed"]},
      reason_code: @emptyable_string,
      endpoint_id: %Schema{type: :string},
      route: %Schema{type: :string},
      method: %Schema{type: :string},
      target_origin: %Schema{type: :string},
      target_path: %Schema{type: :string},
      request_bytes: @string_or_non_negative_integer,
      response_bytes: @string_or_non_negative_integer,
      credential_handle_used: @boolean_or_string,
      proxy_id: @emptyable_string,
      fallback_reason: @emptyable_string,
      payload: %Schema{type: :string},
      content: %Schema{type: :string},
      raw: %Schema{type: :string},
      request_body: %Schema{type: :string}
    },
    required: [:operation, :result]
  }
  @sensitivity_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      plaintext_scope_kind: %Schema{type: :string},
      plaintext_bytes: @string_or_non_negative_integer,
      egress_bytes: @non_negative_integer,
      storage_bytes: @non_negative_integer,
      debug: %Schema{type: :string}
    },
    required: [:plaintext_scope_kind, :plaintext_bytes, :egress_bytes, :storage_bytes]
  }
  @correlation_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      request_id: %Schema{oneOf: [@emptyable_string, @runtime_audit_rejected_object]},
      capability_id: %Schema{type: :string},
      execution_context_id: @emptyable_string,
      authority_event_ref: @emptyable_string,
      request_body: %Schema{type: :string}
    },
    required: [:request_id, :capability_id, :execution_context_id, :authority_event_ref]
  }
  @resource_ref_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      document_id: @emptyable_string,
      selected_document_ids: %Schema{type: :array, items: %Schema{type: :string}},
      block_id: @emptyable_string,
      editor_id: @emptyable_string,
      selection_range: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          anchor: @non_negative_integer,
          head: @non_negative_integer
        },
        required: [:anchor, :head]
      },
      context_range: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          anchor: @non_negative_integer,
          head: @non_negative_integer
        },
        required: [:anchor, :head]
      },
      max_bytes: @non_negative_integer,
      max_documents: @non_negative_integer
    }
  }

  OpenApiSpex.schema(%{
    title: "PluginRuntimeAuditRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.security-audit-event"]},
      version: %Schema{type: :integer, enum: [1]},
      event_id: %Schema{type: :string, minLength: 1},
      class: %Schema{type: :string, enum: ["security_runtime"]},
      type: %Schema{type: :string, minLength: 1},
      plugin_id: %Schema{type: :string, minLength: 1},
      package_id: %Schema{type: :string, minLength: 1},
      application_id: %Schema{type: :string, minLength: 1},
      activation_id: %Schema{type: :string, minLength: 1},
      owner_scope_kind: %Schema{type: :string, enum: ["workspace", "user"]},
      state_head_hash: %Schema{type: :string, minLength: 1},
      consent_head_hash: %Schema{type: :string, minLength: 1},
      capability_grant_id: %Schema{type: :string, minLength: 1},
      consent_epoch: %Schema{type: :integer, minimum: 1},
      frame_generation: %Schema{type: :integer, minimum: 1},
      frame_scope: %Schema{type: :string, enum: ["primary", "secondary"]},
      workspace_id: %Schema{type: :string, format: :uuid},
      bundle_hash: %Schema{type: :string, minLength: 1},
      manifest_hash: %Schema{type: :string, minLength: 1},
      capability_id: %Schema{type: :string},
      request_id: @emptyable_string,
      execution_context_id: @emptyable_string,
      context_kind: @emptyable_string,
      payload_kind: %Schema{type: :string},
      plaintext_scope_kind: %Schema{type: :string},
      plaintext_bytes: @non_negative_integer,
      resource_ref: @resource_ref_schema,
      actor: @actor_schema,
      operation: %Schema{type: :string},
      result: %Schema{type: :string, enum: ["allow", "deny"]},
      reasonCode: %Schema{type: :string},
      contextKind: %Schema{type: :string},
      payloadKind: %Schema{type: :string},
      scope: @scope_schema,
      resource: @resource_schema,
      action: @action_schema,
      sensitivity: @sensitivity_schema,
      correlation: @correlation_schema,
      created_at: %Schema{type: :string}
    },
    required: [
      :type,
      :plugin_id,
      :package_id,
      :application_id,
      :activation_id,
      :owner_scope_kind,
      :capability_grant_id,
      :consent_epoch,
      :frame_generation,
      :workspace_id,
      :bundle_hash,
      :manifest_hash
    ]
  })
end
