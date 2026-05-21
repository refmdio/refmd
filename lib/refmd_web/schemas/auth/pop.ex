defmodule RefMDWeb.Schemas.PopChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @uuid %Schema{type: :string, format: :uuid}
  @checkpoint_sequence %Schema{type: :integer, minimum: 1}

  @user_actor %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["device"]},
      user_id: @uuid,
      device_id: @uuid,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      key_scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      key_scope_id: @uuid,
      key_checkpoint_sequence: @checkpoint_sequence,
      key_checkpoint_hash: %Schema{type: :string}
    },
    required: [
      :signer_kind,
      :user_id,
      :device_id,
      :signing_key_id,
      :key_scope_kind,
      :key_scope_id,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  }

  @share_actor %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["share_participant_device"]},
      share_id: @uuid,
      share_participant_principal_id: @uuid,
      share_participant_device_id: @uuid,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      key_scope_kind: %Schema{type: :string, enum: ["workspace"]},
      key_scope_id: @uuid,
      key_checkpoint_sequence: @checkpoint_sequence,
      key_checkpoint_hash: %Schema{type: :string}
    },
    required: [
      :signer_kind,
      :share_id,
      :share_participant_principal_id,
      :share_participant_device_id,
      :signing_key_id,
      :key_scope_kind,
      :key_scope_id,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  }

  @user_session %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      session_id_hash: %Schema{type: :string},
      session_kind: %Schema{type: :string, enum: ["user"]},
      is_recovery: %Schema{type: :boolean}
    },
    required: [:session_id_hash, :session_kind, :is_recovery]
  }

  @share_session %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      session_id_hash: %Schema{type: :string},
      session_kind: %Schema{type: :string, enum: ["share_participant"]},
      share_id: @uuid,
      is_recovery: %Schema{type: :boolean}
    },
    required: [:session_id_hash, :session_kind, :share_id, :is_recovery]
  }

  OpenApiSpex.schema(%{
    title: "PopChallengeResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      actor: %Schema{oneOf: [@user_actor, @share_actor]},
      session: %Schema{oneOf: [@user_session, @share_session]},
      challenge: %Schema{type: :string}
    },
    required: [:actor, :session, :challenge]
  })
end
