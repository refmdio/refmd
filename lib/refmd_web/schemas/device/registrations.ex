defmodule RefMDWeb.Schemas.CreateDeviceRegistrationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @responder_prekey_payload %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.responder-prekey"]},
      version: %Schema{type: :integer, enum: [1]},
      purpose: %Schema{
        type: :string,
        enum: ["umk_distribution", "trust_transfer", "device_approval_kek_initial"]
      },
      prekey_id: %Schema{type: :string, format: :uuid},
      responder_signer_kind: %Schema{type: :string, enum: ["device"]},
      responder_user_id: %Schema{type: :string, format: :uuid},
      responder_device_id: %Schema{type: :string, format: :uuid},
      responder_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      x25519_ephemeral_public: %Schema{type: :string},
      mlkem768_ephemeral_public: %Schema{type: :string},
      mlkem768_ephemeral_public_hash: RefMDWeb.Schemas.Blake3Base64Url,
      operation_id: %Schema{type: :string, format: :uuid},
      issued_at_event_sequence: %Schema{type: :integer},
      expires_event_sequence: %Schema{type: :integer},
      server_challenge: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :purpose,
      :prekey_id,
      :responder_signer_kind,
      :responder_user_id,
      :responder_device_id,
      :responder_signing_key_id,
      :x25519_ephemeral_public,
      :mlkem768_ephemeral_public,
      :mlkem768_ephemeral_public_hash,
      :operation_id,
      :issued_at_event_sequence,
      :expires_event_sequence,
      :server_challenge
    ]
  }

  @responder_prekey_record %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: @responder_prekey_payload,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:payload, :signature]
  }

  @device_approval_prekey_entry %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      prekey: @responder_prekey_record
    },
    required: [:workspace_id, :prekey]
  }

  @ake_responder_prekeys_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      umk_distribution: @responder_prekey_record,
      trust_transfer: @responder_prekey_record,
      device_approval_kek_initial: %Schema{
        type: :array,
        items: @device_approval_prekey_entry
      }
    },
    required: [:umk_distribution, :trust_transfer, :device_approval_kek_initial]
  }

  @base_properties %{
    device_id: %Schema{type: :string, format: :uuid},
    name: %Schema{type: :string},
    device_type: %Schema{type: :string},
    identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
    device_hybrid_signing_public_key_material:
      RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
    device_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
    device_hybrid_encryption_public_key_material:
      RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
    device_encryption_key_id: %Schema{type: :string},
    client_nonce: %Schema{type: :string},
    registration_challenge: %Schema{type: :string}
  }

  @base_required [
    :device_id,
    :identity_signing_key_id,
    :device_hybrid_signing_public_key_material,
    :device_signing_key_id,
    :device_hybrid_encryption_public_key_material,
    :device_encryption_key_id,
    :client_nonce,
    :registration_challenge
  ]

  @normal_registration_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: Map.put(@base_properties, :ake_responder_prekeys, @ake_responder_prekeys_schema),
    required: @base_required ++ [:ake_responder_prekeys]
  }

  @recovery_registration_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: @base_properties,
    required: @base_required
  }

  OpenApiSpex.schema(%{
    title: "CreateDeviceRegistrationRequest",
    oneOf: [@normal_registration_schema, @recovery_registration_schema]
  })
end

defmodule RefMDWeb.Schemas.CreateDeviceRegistrationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDeviceRegistrationResponse",
    type: :object,
    properties: %{
      status: %Schema{type: :string}
    },
    required: [:status]
  })
end

defmodule RefMDWeb.Schemas.DeviceRegistrationInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @responder_prekey_payload %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.responder-prekey"]},
      version: %Schema{type: :integer, enum: [1]},
      purpose: %Schema{
        type: :string,
        enum: ["umk_distribution", "trust_transfer", "device_approval_kek_initial"]
      },
      prekey_id: %Schema{type: :string, format: :uuid},
      responder_signer_kind: %Schema{type: :string, enum: ["device"]},
      responder_user_id: %Schema{type: :string, format: :uuid},
      responder_device_id: %Schema{type: :string, format: :uuid},
      responder_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      x25519_ephemeral_public: %Schema{type: :string},
      mlkem768_ephemeral_public: %Schema{type: :string},
      mlkem768_ephemeral_public_hash: RefMDWeb.Schemas.Blake3Base64Url,
      operation_id: %Schema{type: :string, format: :uuid},
      issued_at_event_sequence: %Schema{type: :integer},
      expires_event_sequence: %Schema{type: :integer},
      server_challenge: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :purpose,
      :prekey_id,
      :responder_signer_kind,
      :responder_user_id,
      :responder_device_id,
      :responder_signing_key_id,
      :x25519_ephemeral_public,
      :mlkem768_ephemeral_public,
      :mlkem768_ephemeral_public_hash,
      :operation_id,
      :issued_at_event_sequence,
      :expires_event_sequence,
      :server_challenge
    ]
  }

  @responder_prekey_record %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: @responder_prekey_payload,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:payload, :signature]
  }

  @device_approval_prekey_entry %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      prekey: @responder_prekey_record
    },
    required: [:workspace_id, :prekey]
  }

  @ake_responder_prekeys_schema %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      umk_distribution: @responder_prekey_record,
      trust_transfer: @responder_prekey_record,
      device_approval_kek_initial: %Schema{
        type: :array,
        items: @device_approval_prekey_entry
      }
    },
    required: [:umk_distribution, :trust_transfer, :device_approval_kek_initial]
  }

  OpenApiSpex.schema(%{
    title: "DeviceRegistrationInfo",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
      encryption_key_id: %Schema{type: :string},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      client_nonce: %Schema{type: :string},
      pending_registration_challenge_hash: %Schema{type: :string, nullable: true},
      ake_responder_prekeys: %Schema{
        allOf: [@ake_responder_prekeys_schema],
        nullable: true
      },
      ip_address: %Schema{type: :string, nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      expires_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :client_nonce,
      :created_at,
      :expires_at
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceRegistrationsResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRegistrationsResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      devices: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.DeviceRegistrationInfo}
    },
    required: [:devices]
  })
end

defmodule RefMDWeb.Schemas.DeviceRegistrationStatusResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceRegistrationStatusResponse",
    type: :object,
    properties: %{
      status: %Schema{type: :string, enum: ["pending", "approved", "expired"]}
    },
    required: [:status]
  })
end
