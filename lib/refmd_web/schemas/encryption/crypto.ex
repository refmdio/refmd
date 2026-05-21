defmodule RefMDWeb.Schemas.HybridSigningPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "HybridSigningPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signing-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{
        type: :string,
        enum: [
          "identity",
          "device",
          "share_participant_device",
          "invitation_redeem_authority"
        ]
      },
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      ed25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mldsa65_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 2603,
        maxLength: 2603
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :ed25519_public,
      :mldsa65_public
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareCapabilitySigningPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"
  @hash_schema %Schema{
    type: :string,
    pattern: "^[A-Za-z0-9_-]{43}$",
    minLength: 43,
    maxLength: 43
  }

  OpenApiSpex.schema(%{
    title: "ShareCapabilitySigningPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signing-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["share_capability"]},
      owner_id: @hash_schema,
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      ed25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mldsa65_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 2603,
        maxLength: 2603
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :ed25519_public,
      :mldsa65_public
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "IdentityHybridSigningPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signing-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["identity"]},
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      ed25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mldsa65_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 2603,
        maxLength: 2603
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :ed25519_public,
      :mldsa65_public
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "DeviceHybridSigningPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signing-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["device"]},
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      ed25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mldsa65_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 2603,
        maxLength: 2603
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :ed25519_public,
      :mldsa65_public
    ]
  })
end

defmodule RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "HybridEncryptionPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-encryption-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{
        type: :string,
        enum: [
          "identity",
          "device",
          "share_participant_device"
        ]
      },
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{
        type: :string,
        enum: [
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
        ]
      },
      suite_rank: %Schema{type: :integer, enum: [1000]},
      x25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mlkem768_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1579,
        maxLength: 1579
      },
      hybrid_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1622,
        maxLength: 1622
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :x25519_public,
      :mlkem768_public,
      :hybrid_public
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "IdentityHybridEncryptionPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-encryption-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["identity"]},
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{
        type: :string,
        enum: [
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
        ]
      },
      suite_rank: %Schema{type: :integer, enum: [1000]},
      x25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mlkem768_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1579,
        maxLength: 1579
      },
      hybrid_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1622,
        maxLength: 1622
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :x25519_public,
      :mlkem768_public,
      :hybrid_public
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "DeviceHybridEncryptionPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-encryption-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["device"]},
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{
        type: :string,
        enum: [
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
        ]
      },
      suite_rank: %Schema{type: :integer, enum: [1000]},
      x25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mlkem768_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1579,
        maxLength: 1579
      },
      hybrid_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1622,
        maxLength: 1622
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :x25519_public,
      :mlkem768_public,
      :hybrid_public
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareParticipantDeviceSigningPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "ShareParticipantDeviceSigningPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signing-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["share_participant_device"]},
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      ed25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mldsa65_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 2603,
        maxLength: 2603
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :ed25519_public,
      :mldsa65_public
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareParticipantDeviceEncryptionPublicKeyMaterial do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"

  OpenApiSpex.schema(%{
    title: "ShareParticipantDeviceEncryptionPublicKeyMaterial",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-encryption-key-material"]},
      version: %Schema{type: :integer, enum: [1]},
      owner_kind: %Schema{type: :string, enum: ["share_participant_device"]},
      owner_id: %Schema{type: :string, minLength: 1},
      suite_id: %Schema{
        type: :string,
        enum: [
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
        ]
      },
      suite_rank: %Schema{type: :integer, enum: [1000]},
      x25519_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 43,
        maxLength: 43
      },
      mlkem768_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1579,
        maxLength: 1579
      },
      hybrid_public: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 1622,
        maxLength: 1622
      }
    },
    required: [
      :protocol,
      :version,
      :owner_kind,
      :owner_id,
      :suite_id,
      :suite_rank,
      :x25519_public,
      :mlkem768_public,
      :hybrid_public
    ]
  })
end

defmodule RefMDWeb.Schemas.HybridSignature do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @base64url_pattern "^[A-Za-z0-9_-]+$"
  @hash_pattern "^[A-Za-z0-9_-]{43}$"

  OpenApiSpex.schema(%{
    title: "HybridSignature",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature"]},
      version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string, enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]},
      suite_rank: %Schema{type: :integer, enum: [1000]},
      signing_key_id: %Schema{
        type: :string,
        pattern: @hash_pattern,
        minLength: 43,
        maxLength: 43
      },
      transcript_hash: %Schema{
        type: :string,
        pattern: @hash_pattern,
        minLength: 43,
        maxLength: 43
      },
      ed25519: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 86,
        maxLength: 86
      },
      mldsa65: %Schema{
        type: :string,
        pattern: @base64url_pattern,
        minLength: 4412,
        maxLength: 4412
      }
    },
    required: [
      :protocol,
      :version,
      :suite_id,
      :suite_rank,
      :signing_key_id,
      :transcript_hash,
      :ed25519,
      :mldsa65
    ]
  })
end
