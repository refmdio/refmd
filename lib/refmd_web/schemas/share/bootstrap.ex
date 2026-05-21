defmodule RefMDWeb.Schemas.DocumentShareRoot do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentShareRoot",
    type: :object,
    properties: %{
      kind: %Schema{type: :string, enum: ["document"]},
      document_token: %Schema{type: :string}
    },
    required: [:kind, :document_token]
  })
end

defmodule RefMDWeb.Schemas.FolderShareRoot do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "FolderShareRoot",
    type: :object,
    properties: %{
      kind: %Schema{type: :string, enum: ["folder"]},
      folder_token: %Schema{type: :string}
    },
    required: [:kind, :folder_token]
  })
end

defmodule RefMDWeb.Schemas.ShareLandingResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareLandingResponse",
    type: :object,
    properties: %{
      share: %Schema{
        type: :object,
        properties: %{
          id: %Schema{type: :string, format: :uuid},
          document_id: %Schema{type: :string, format: :uuid},
          scope: %Schema{type: :string, enum: ["document", "folder"]},
          permission: %Schema{type: :string, enum: ["view", "edit"]},
          created_event_hash: %Schema{type: :string},
          latest_bootstrap_event_hash: %Schema{type: :string},
          capability_context_hash: %Schema{type: :string},
          share_capability_secret_commitment: %Schema{type: :string},
          password_capability_secret_commitment: %Schema{type: :string},
          password_protected: %Schema{type: :boolean}
        },
        required: [
          :id,
          :document_id,
          :scope,
          :permission,
          :created_event_hash,
          :latest_bootstrap_event_hash,
          :capability_context_hash,
          :share_capability_secret_commitment,
          :password_capability_secret_commitment,
          :password_protected
        ]
      },
      password_challenge_required: %Schema{type: :boolean, nullable: true},
      root: %Schema{
        nullable: true,
        oneOf: [
          RefMDWeb.Schemas.DocumentShareRoot,
          RefMDWeb.Schemas.FolderShareRoot
        ]
      }
    },
    required: [:share]
  })
end

defmodule RefMDWeb.Schemas.ShareCapabilityAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  defmodule Transcript do
    alias OpenApiSpex.Schema
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ShareCapabilityAuthorizationTranscript",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature-transcript"]},
        label: %Schema{type: :string, enum: ["RefMD hybrid signature transcript v1"]},
        version: %Schema{type: :integer, enum: [1]},
        transcript_owner: %Schema{
          type: :string,
          enum: ["refmd.share.capability_authorization"]
        },
        surface_id: %Schema{type: :string, enum: ["share_capability_authorization"]},
        surface_variant: %Schema{type: :string, enum: ["none"]},
        signing_purpose: %Schema{type: :string, enum: ["share_capability_authorization"]},
        owner_kind: %Schema{type: :string, enum: ["share_capability"]},
        owner_id: %Schema{type: :string},
        signature_suite_id: %Schema{
          type: :string,
          enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]
        },
        signature_suite_rank: %Schema{type: :integer, enum: [1000]},
        subject_hash: %Schema{type: :string},
        subject_protocol: %Schema{
          type: :string,
          enum: ["refmd.share.capability_authorization"]
        },
        subject_version: %Schema{type: :integer, enum: [1]},
        authorization: %Schema{
          type: :object,
          additionalProperties: false,
          properties: %{
            token_hash: %Schema{type: :string},
            workspace_pin_bootstrap_hash: %Schema{type: :string}
          },
          required: [:token_hash, :workspace_pin_bootstrap_hash]
        },
        share_state: %Schema{
          type: :object,
          additionalProperties: false,
          properties: %{
            share_id: %Schema{type: :string, format: :uuid},
            scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
            scope_id: %Schema{type: :string, format: :uuid},
            permission: %Schema{type: :string, enum: ["view", "edit"]},
            password_protected: %Schema{type: :boolean},
            created_event_hash: %Schema{type: :string},
            latest_bootstrap_event_hash: %Schema{type: :string},
            capability_context_hash: %Schema{type: :string},
            share_capability_secret_commitment: %Schema{type: :string},
            password_capability_secret_commitment: %Schema{type: :string}
          },
          required: [
            :share_id,
            :scope_kind,
            :scope_id,
            :permission,
            :password_protected,
            :created_event_hash,
            :latest_bootstrap_event_hash,
            :capability_context_hash,
            :share_capability_secret_commitment,
            :password_capability_secret_commitment
          ]
        }
      },
      required: [
        :protocol,
        :label,
        :version,
        :transcript_owner,
        :surface_id,
        :surface_variant,
        :signing_purpose,
        :owner_kind,
        :owner_id,
        :signature_suite_id,
        :signature_suite_rank,
        :subject_hash,
        :subject_protocol,
        :subject_version,
        :authorization,
        :share_state
      ]
    })
  end

  OpenApiSpex.schema(%{
    title: "ShareCapabilityAuthorization",
    type: :object,
    additionalProperties: false,
    properties: %{
      transcript: Transcript,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:transcript, :signature]
  })
end

defmodule RefMDWeb.Schemas.ShareParticipantDeviceAuthorization do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  defmodule Transcript do
    alias OpenApiSpex.Schema
    require OpenApiSpex

    OpenApiSpex.schema(%{
      title: "ShareParticipantDeviceAuthorizationTranscript",
      type: :object,
      additionalProperties: false,
      properties: %{
        protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature-transcript"]},
        label: %Schema{type: :string, enum: ["RefMD hybrid signature transcript v1"]},
        version: %Schema{type: :integer, enum: [1]},
        transcript_owner: %Schema{
          type: :string,
          enum: ["refmd.share.participant_device_authorization"]
        },
        surface_id: %Schema{type: :string, enum: ["share_participant_device_authorization"]},
        surface_variant: %Schema{type: :string, enum: ["none"]},
        signing_purpose: %Schema{type: :string, enum: ["share_participant_device_authorization"]},
        owner_kind: %Schema{type: :string, enum: ["share_participant_device"]},
        owner_id: %Schema{type: :string, format: :uuid},
        signature_suite_id: %Schema{
          type: :string,
          enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]
        },
        signature_suite_rank: %Schema{type: :integer, enum: [1000]},
        share_id: %Schema{type: :string, format: :uuid},
        share_session_id: %Schema{type: :string, format: :uuid},
        share_participant_principal_id: %Schema{type: :string, format: :uuid},
        share_participant_device_id: %Schema{type: :string, format: :uuid},
        participant_signing_key_id: %Schema{type: :string},
        participant_encryption_key_id: %Schema{type: :string},
        capability_context_hash: %Schema{type: :string},
        share_created_event_hash: %Schema{type: :string},
        latest_bootstrap_event_hash: %Schema{type: :string},
        scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
        scope_id: %Schema{type: :string, format: :uuid},
        permission: %Schema{type: :string, enum: ["view", "edit"]}
      },
      required: [
        :protocol,
        :label,
        :version,
        :transcript_owner,
        :surface_id,
        :surface_variant,
        :signing_purpose,
        :owner_kind,
        :owner_id,
        :signature_suite_id,
        :signature_suite_rank,
        :share_id,
        :share_session_id,
        :share_participant_principal_id,
        :share_participant_device_id,
        :participant_signing_key_id,
        :participant_encryption_key_id,
        :capability_context_hash,
        :share_created_event_hash,
        :latest_bootstrap_event_hash,
        :scope_kind,
        :scope_id,
        :permission
      ]
    })
  end

  OpenApiSpex.schema(%{
    title: "ShareParticipantDeviceAuthorization",
    type: :object,
    additionalProperties: false,
    properties: %{
      transcript: Transcript,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:transcript, :signature]
  })
end

defmodule RefMDWeb.Schemas.ShareBootstrapRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareBootstrapRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      display_name: %Schema{type: :string},
      share_participant_device_id: %Schema{type: :string, format: :uuid},
      share_participant_principal_id: %Schema{type: :string, format: :uuid},
      share_participant_session_id: %Schema{type: :string, format: :uuid},
      hybrid_signing_public_key_material:
        RefMDWeb.Schemas.ShareParticipantDeviceSigningPublicKeyMaterial,
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.ShareParticipantDeviceEncryptionPublicKeyMaterial,
      share_capability_authorization: RefMDWeb.Schemas.ShareCapabilityAuthorization,
      share_participant_device_authorization: RefMDWeb.Schemas.ShareParticipantDeviceAuthorization
    },
    required: [
      :display_name,
      :share_participant_device_id,
      :share_participant_principal_id,
      :share_participant_session_id,
      :hybrid_signing_public_key_material,
      :hybrid_encryption_public_key_material,
      :share_capability_authorization,
      :share_participant_device_authorization
    ]
  })
end

defmodule RefMDWeb.Schemas.SharePasswordChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SharePasswordChallengeResponse",
    type: :object,
    properties: %{
      challenge: %Schema{type: :string},
      salt: %Schema{type: :string},
      kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:challenge, :salt, :kdf_params]
  })
end

defmodule RefMDWeb.Schemas.SharePasswordChallengeRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SharePasswordChallengeRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      response: %Schema{type: :string},
      display_name: %Schema{type: :string},
      share_participant_device_id: %Schema{type: :string, format: :uuid},
      share_participant_principal_id: %Schema{type: :string, format: :uuid},
      share_participant_session_id: %Schema{type: :string, format: :uuid},
      hybrid_signing_public_key_material:
        RefMDWeb.Schemas.ShareParticipantDeviceSigningPublicKeyMaterial,
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.ShareParticipantDeviceEncryptionPublicKeyMaterial,
      share_capability_authorization: RefMDWeb.Schemas.ShareCapabilityAuthorization,
      share_participant_device_authorization:
        RefMDWeb.Schemas.ShareParticipantDeviceAuthorization,
      password_challenge_hash: %Schema{type: :string}
    },
    required: [
      :response,
      :display_name,
      :share_participant_device_id,
      :share_participant_principal_id,
      :share_participant_session_id,
      :hybrid_signing_public_key_material,
      :hybrid_encryption_public_key_material,
      :share_capability_authorization,
      :share_participant_device_authorization,
      :password_challenge_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareParticipantInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareParticipantInfo",
    type: :object,
    properties: %{
      principal_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      session_id: %Schema{type: :string, format: :uuid},
      grant: %Schema{type: :string, enum: ["view", "edit"]}
    },
    required: [:principal_id, :device_id, :session_id, :grant]
  })
end

defmodule RefMDWeb.Schemas.ShareBootstrapResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareBootstrapResponse",
    type: :object,
    properties: %{
      root: %Schema{
        oneOf: [
          RefMDWeb.Schemas.DocumentShareRoot,
          RefMDWeb.Schemas.FolderShareRoot
        ]
      },
      share_id: %Schema{type: :string, format: :uuid},
      scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
      scope_id: %Schema{type: :string, format: :uuid},
      created_event_hash: %Schema{type: :string},
      latest_bootstrap_event_hash: %Schema{type: :string},
      capability_context_hash: %Schema{type: :string},
      share_capability_secret_commitment: %Schema{type: :string},
      password_capability_secret_commitment: %Schema{type: :string},
      participant: RefMDWeb.Schemas.ShareParticipantInfo
    },
    required: [
      :root,
      :share_id,
      :scope_kind,
      :scope_id,
      :created_event_hash,
      :latest_bootstrap_event_hash,
      :capability_context_hash,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :participant
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareDocumentBootstrapResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareDocumentBootstrapResponse",
    type: :object,
    properties: %{
      share_token_hash: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid},
      authorization_share_id: %Schema{type: :string, format: :uuid},
      scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
      scope_id: %Schema{type: :string, format: :uuid},
      created_event_hash: %Schema{type: :string},
      latest_bootstrap_event_hash: %Schema{type: :string},
      capability_context_hash: %Schema{type: :string},
      share_capability_secret_commitment: %Schema{type: :string},
      password_capability_secret_commitment: %Schema{type: :string},
      document_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      workspace_pin_bootstrap: %Schema{
        allOf: [RefMDWeb.Schemas.WorkspacePinBootstrap],
        nullable: true
      },
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      },
      verification_directory: RefMDWeb.Schemas.ShareVerificationDirectory
    },
    required: [
      :share_token_hash,
      :share_id,
      :authorization_share_id,
      :scope_kind,
      :scope_id,
      :created_event_hash,
      :latest_bootstrap_event_hash,
      :capability_context_hash,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :document_id,
      :workspace_id,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :permission,
      :password_protected,
      :encrypted_dek,
      :nonce,
      :workspace_pin_bootstrap,
      :workspace_key_directory_checkpoint,
      :verification_directory
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareDocumentBootstrapRequiredResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareDocumentBootstrapRequiredResponse",
    type: :object,
    properties: %{
      share_token_hash: %Schema{type: :string},
      bootstrap_required: %Schema{type: :boolean}
    },
    required: [:share_token_hash, :bootstrap_required]
  })
end

defmodule RefMDWeb.Schemas.ShareDocumentRouteMetadataResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareDocumentRouteMetadataResponse",
    type: :object,
    properties: %{
      share_token_hash: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      bootstrap_required: %Schema{type: :boolean}
    },
    required: [
      :share_token_hash,
      :share_id,
      :document_id,
      :workspace_id,
      :permission,
      :password_protected,
      :bootstrap_required
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareFolderRouteMetadataResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareFolderRouteMetadataResponse",
    type: :object,
    properties: %{
      share_token_hash: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid},
      folder_id: %Schema{type: :string, format: :uuid},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      bootstrap_required: %Schema{type: :boolean}
    },
    required: [
      :share_token_hash,
      :share_id,
      :folder_id,
      :permission,
      :password_protected,
      :bootstrap_required
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareTreeEntry do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareTreeEntry",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      share_id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer, nullable: true},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      key_version: %Schema{type: :integer},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string, nullable: true},
      workspace_pin_bootstrap: %Schema{
        allOf: [RefMDWeb.Schemas.WorkspacePinBootstrap],
        nullable: true
      },
      document_token: %Schema{type: :string, nullable: true},
      folder_token: %Schema{type: :string, nullable: true}
    },
    required: [
      :id,
      :share_id,
      :doc_type,
      :parent_id,
      :position,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :key_version,
      :encrypted_dek,
      :nonce,
      :workspace_pin_bootstrap,
      :document_token,
      :folder_token
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareFolderBootstrapResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareFolderBootstrapResponse",
    type: :object,
    properties: %{
      share_token_hash: %Schema{type: :string},
      share_id: %Schema{type: :string, format: :uuid},
      scope_kind: %Schema{type: :string, enum: ["document", "folder"]},
      scope_id: %Schema{type: :string, format: :uuid},
      created_event_hash: %Schema{type: :string},
      latest_bootstrap_event_hash: %Schema{type: :string},
      capability_context_hash: %Schema{type: :string},
      share_capability_secret_commitment: %Schema{type: :string},
      password_capability_secret_commitment: %Schema{type: :string},
      workspace_id: %Schema{type: :string, format: :uuid},
      permission: %Schema{type: :string, enum: ["view", "edit"]},
      password_protected: %Schema{type: :boolean},
      workspace_pin_bootstrap: %Schema{
        allOf: [RefMDWeb.Schemas.WorkspacePinBootstrap],
        nullable: true
      },
      workspace_key_directory_checkpoint: %Schema{
        allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope],
        nullable: true
      },
      verification_directory: RefMDWeb.Schemas.ShareVerificationDirectory,
      folder: RefMDWeb.Schemas.ShareTreeEntry,
      entries: %Schema{type: :array, items: RefMDWeb.Schemas.ShareTreeEntry}
    },
    required: [
      :share_token_hash,
      :share_id,
      :scope_kind,
      :scope_id,
      :created_event_hash,
      :latest_bootstrap_event_hash,
      :capability_context_hash,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :workspace_id,
      :permission,
      :password_protected,
      :workspace_pin_bootstrap,
      :workspace_key_directory_checkpoint,
      :verification_directory,
      :folder,
      :entries
    ]
  })
end

defmodule RefMDWeb.Schemas.ShareCanonicalBootstrapRequest do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ShareCanonicalBootstrapRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      authenticated_workspace_pin_bootstrap_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [:authenticated_workspace_pin_bootstrap_hash]
  })
end
