defmodule RefMD.Crypto.Signature.Collaboration do
  @moduledoc false

  @protocol_version 1
  @suite_rank 1000
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"

  @transcript_protocol "refmd.hybrid-signature-transcript"
  @transcript_label "RefMD hybrid signature transcript v1"

  import RefMD.Crypto.Signature.Core, only: [assert_transcript!: 4]

  alias RefMD.Crypto.{Encoding, Hash}
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.SigningSurface

  def build_document_update_transcript!(params) when is_map(params) do
    %{
      owner_kind: owner_kind,
      owner_id: owner_id,
      workspace_id: workspace_id,
      actor_user_id: actor_user_id,
      actor_device_id: actor_device_id,
      signing_key_id: signing_key_id,
      public_data: public_data,
      authority_boundary: authority_boundary,
      ciphertext: ciphertext,
      nonce: nonce
    } = document_operation_params!(params)

    surface = SigningSurface.get_active!("document_update", document_update_variant!(owner_kind))

    subject =
      JCS.canonical_bytes!(%{
        "ciphertext" => ciphertext,
        "nonce" => nonce,
        "publicData" => public_data
      })

    transcript = %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => "document_update",
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank,
      "document_id" => public_data["docId"],
      "ciphertext_hash" => ciphertext_hash(ciphertext),
      "nonce" => nonce,
      "public_data" => public_data,
      "subject_hash" => Hash.blake3_base64url(subject),
      "subject_protocol" => "refmd.ws.document_update",
      "subject_version" => @protocol_version,
      "actor" =>
        collaboration_actor(
          owner_kind,
          actor_user_id,
          actor_device_id,
          signing_key_id,
          workspace_id,
          public_data
        ),
      "authority_boundary" => authority_boundary
    }

    assert_transcript!(transcript, "document_update", owner_kind, owner_id)
    transcript
  end

  def build_document_update_transcript!(_),
    do: raise(ArgumentError, "document_update_transcript_invalid")

  def build_document_snapshot_transcript!(params) when is_map(params) do
    %{
      owner_kind: owner_kind,
      owner_id: owner_id,
      workspace_id: workspace_id,
      actor_user_id: actor_user_id,
      actor_device_id: actor_device_id,
      signing_key_id: signing_key_id,
      public_data: public_data,
      authority_boundary: authority_boundary,
      ciphertext: ciphertext,
      nonce: nonce
    } = document_operation_params!(params)

    surface =
      SigningSurface.get_active!("document_snapshot", document_update_variant!(owner_kind))

    public_data_subject = normalize_snapshot_public_data_for_subject(public_data)

    subject =
      JCS.canonical_bytes!(%{
        "ciphertext" => ciphertext,
        "nonce" => nonce,
        "publicData" => public_data_subject
      })

    transcript = %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => "document_snapshot",
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank,
      "document_id" => public_data["docId"],
      "snapshot_id" => public_data["snapshotId"],
      "ciphertext_hash" => ciphertext_hash(ciphertext),
      "nonce" => nonce,
      "public_data" => public_data_subject,
      "subject_hash" => Hash.blake3_base64url(subject),
      "subject_protocol" => "refmd.ws.document_snapshot",
      "subject_version" => @protocol_version,
      "actor" =>
        collaboration_actor(
          owner_kind,
          actor_user_id,
          actor_device_id,
          signing_key_id,
          workspace_id,
          public_data
        ),
      "authority_boundary" => authority_boundary
    }

    assert_transcript!(transcript, "document_snapshot", owner_kind, owner_id)
    transcript
  end

  def build_document_snapshot_transcript!(_),
    do: raise(ArgumentError, "document_snapshot_transcript_invalid")

  defp document_operation_params!(params) do
    %{
      owner_kind: assert_binary!(params.owner_kind, "owner_kind_invalid"),
      owner_id: assert_binary!(params.owner_id, "owner_id_invalid"),
      workspace_id: assert_binary!(params.workspace_id, "workspace_id_invalid"),
      actor_user_id: assert_binary!(params.actor_user_id, "actor_user_id_invalid"),
      actor_device_id: assert_binary!(params.actor_device_id, "actor_device_id_invalid"),
      signing_key_id: assert_binary!(params.signing_key_id, "signing_key_id_invalid"),
      public_data: assert_map!(params.public_data, "public_data_invalid"),
      authority_boundary: assert_map!(params.authority_boundary, "authority_boundary_invalid"),
      ciphertext: assert_binary!(params.ciphertext, "ciphertext_invalid"),
      nonce: assert_binary!(params.nonce, "nonce_invalid")
    }
  end

  defp editor_ephemeral_params!(params) do
    params
    |> Map.take([
      :owner_kind,
      :owner_id,
      :workspace_id,
      :actor_user_id,
      :actor_device_id,
      :signing_key_id,
      :public_data,
      :authority_boundary,
      :ciphertext,
      :nonce
    ])
    |> document_operation_params!()
  end

  defp normalize_snapshot_public_data_for_subject(public_data) do
    Map.update(public_data, "parentSnapshotId", "GENESIS", fn
      nil -> "GENESIS"
      value -> value
    end)
  end

  defp collaboration_actor(
         "share_participant_device",
         actor_user_id,
         actor_device_id,
         signing_key_id,
         workspace_id,
         public_data
       ) do
    %{
      "key_checkpoint_hash" => public_data["keyCheckpointHash"],
      "key_checkpoint_sequence" => public_data["keyCheckpointSequence"],
      "key_scope_id" => workspace_id,
      "key_scope_kind" => "workspace",
      "share_id" => public_data["authorityId"],
      "share_participant_device_id" => actor_device_id,
      "share_participant_principal_id" => actor_user_id,
      "signer_kind" => "share_participant_device",
      "signing_key_id" => signing_key_id
    }
  end

  defp collaboration_actor(
         _owner_kind,
         actor_user_id,
         actor_device_id,
         signing_key_id,
         workspace_id,
         public_data
       ) do
    %{
      "device_id" => actor_device_id,
      "key_checkpoint_hash" => public_data["keyCheckpointHash"],
      "key_checkpoint_sequence" => public_data["keyCheckpointSequence"],
      "key_scope_id" => workspace_id,
      "key_scope_kind" => "workspace",
      "signer_kind" => "workspace_device",
      "signing_key_id" => signing_key_id,
      "user_id" => actor_user_id
    }
  end

  defp ciphertext_hash(ciphertext) do
    ciphertext
    |> Encoding.decode_base64url!()
    |> Hash.blake3_base64url()
  end

  defp assert_binary!(value, _reason) when is_binary(value), do: value
  defp assert_binary!(_value, reason), do: raise(ArgumentError, reason)

  defp assert_map!(value, _reason) when is_map(value), do: value
  defp assert_map!(_value, reason), do: raise(ArgumentError, reason)

  def build_editor_ephemeral_transcript!(params) when is_map(params) do
    %{
      owner_kind: owner_kind,
      owner_id: owner_id,
      workspace_id: workspace_id,
      actor_user_id: actor_user_id,
      actor_device_id: actor_device_id,
      signing_key_id: signing_key_id,
      public_data: public_data,
      authority_boundary: authority_boundary,
      ciphertext: ciphertext,
      nonce: nonce
    } = editor_ephemeral_params!(params)

    surface = SigningSurface.get_active!("editor_ephemeral", document_update_variant!(owner_kind))

    subject =
      JCS.canonical_bytes!(%{
        "ciphertext" => ciphertext,
        "nonce" => nonce,
        "publicData" => public_data
      })

    subject_hash = Hash.blake3_base64url(subject)

    transcript = %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => "editor_ephemeral",
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank,
      "subject_hash" => subject_hash,
      "subject_protocol" => "refmd.editor-ephemeral",
      "subject_version" => @protocol_version,
      "actor" =>
        collaboration_actor(
          owner_kind,
          actor_user_id,
          actor_device_id,
          signing_key_id,
          workspace_id,
          public_data
        ),
      "session" => %{
        "workspace_id" => workspace_id,
        "document_id" => public_data["docId"],
        "channel_id" => public_data["docId"],
        "message_nonce" => nonce
      },
      "authority_boundary" => authority_boundary
    }

    assert_transcript!(transcript, "editor_ephemeral", owner_kind, owner_id)
    transcript
  end

  def build_editor_ephemeral_transcript!(_),
    do: raise(ArgumentError, "editor_ephemeral_transcript_invalid")

  def build_editor_ephemeral_session_transcript!(params) when is_map(params) do
    owner_kind = Map.fetch!(params, :owner_kind)
    owner_id = Map.fetch!(params, :owner_id)
    workspace_id = Map.fetch!(params, :workspace_id)
    document_id = Map.fetch!(params, :document_id)
    channel_id = Map.fetch!(params, :channel_id)
    actor_user_id = Map.fetch!(params, :actor_user_id)
    actor_device_id = Map.fetch!(params, :actor_device_id)
    signing_key_id = Map.fetch!(params, :signing_key_id)
    session_id = Map.fetch!(params, :session_id)
    proof_direction = Map.fetch!(params, :proof_direction)
    proof_type = Map.fetch!(params, :proof_type)
    session_nonce = Map.fetch!(params, :session_nonce)
    counter = Map.fetch!(params, :counter)
    expires_event_sequence = Map.fetch!(params, :expires_event_sequence)
    authority_boundary = Map.fetch!(params, :authority_boundary)

    surface =
      SigningSurface.get_active!("editor_ephemeral_session", document_update_variant!(owner_kind))

    session = %{
      "workspace_id" => workspace_id,
      "document_id" => document_id,
      "channel_id" => channel_id,
      "session_id" => session_id,
      "proof_direction" => proof_direction,
      "proof_type" => proof_type,
      "session_nonce" => session_nonce,
      "counter" => counter,
      "expires_event_sequence" => expires_event_sequence
    }

    subject = JCS.canonical_bytes!(session)

    transcript = %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => "editor_ephemeral_session",
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank,
      "subject_hash" => Hash.blake3_base64url(subject),
      "subject_protocol" => "refmd.editor-ephemeral-session",
      "subject_version" => @protocol_version,
      "actor" =>
        editor_ephemeral_session_actor!(
          owner_kind,
          actor_user_id,
          actor_device_id,
          signing_key_id,
          workspace_id,
          Map.fetch!(params, :key_checkpoint_sequence),
          Map.fetch!(params, :key_checkpoint_hash)
        ),
      "session" => session,
      "authority_boundary" => authority_boundary
    }

    assert_transcript!(transcript, "editor_ephemeral_session", owner_kind, owner_id)
    transcript
  end

  def build_editor_ephemeral_session_transcript!(_),
    do: raise(ArgumentError, "editor_ephemeral_session_transcript_invalid")

  defp editor_ephemeral_session_actor!(
         "share_participant_device",
         actor_principal_id,
         actor_device_id,
         signing_key_id,
         workspace_id,
         key_checkpoint_sequence,
         key_checkpoint_hash
       ) do
    %{
      "signer_kind" => "share_participant_device",
      "share_participant_principal_id" => actor_principal_id,
      "share_participant_device_id" => actor_device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => key_checkpoint_sequence,
      "key_checkpoint_hash" => key_checkpoint_hash
    }
  end

  defp editor_ephemeral_session_actor!(
         "device",
         actor_user_id,
         actor_device_id,
         signing_key_id,
         workspace_id,
         key_checkpoint_sequence,
         key_checkpoint_hash
       ) do
    %{
      "signer_kind" => "workspace_device",
      "device_id" => actor_device_id,
      "signing_key_id" => signing_key_id,
      "user_id" => actor_user_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => key_checkpoint_sequence,
      "key_checkpoint_hash" => key_checkpoint_hash
    }
  end

  defp editor_ephemeral_session_actor!(_, _, _, _, _, _, _),
    do: raise(ArgumentError, "editor_ephemeral_session_actor_invalid")

  defp document_update_variant!("device"), do: "workspace_device"
  defp document_update_variant!("share_participant_device"), do: "share_participant_device"
  defp document_update_variant!(_owner_kind), do: raise(ArgumentError, "owner_kind_invalid")
end
