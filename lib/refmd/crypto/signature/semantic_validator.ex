defmodule RefMD.Crypto.Signature.SemanticValidator do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Crypto.Signature.Core
  alias RefMD.Encryption.KeyDirectory.Replay

  @spec validate_transcript!(map(), binary(), binary(), binary()) :: :ok
  def validate_transcript!(transcript, signing_purpose, owner_kind, owner_id) do
    Core.assert_transcript!(transcript, signing_purpose, owner_kind, owner_id)
  end

  @spec validate_device_approval!(map(), binary(), binary(), binary()) :: :ok
  def validate_device_approval!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    assert_binary!(transcript["approval_signature_surface"], "approval_signature_surface_invalid")

    assert_binary!(
      transcript["approving_device_key_directory_proof_hash"],
      "approving_device_key_directory_proof_hash_invalid"
    )
  end

  @spec validate_device_approval!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_device_approval!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_device_approval!(transcript, signing_purpose, owner_kind, owner_id)

    approver =
      required_context_map!(semantic_context, :approver, "device_approval_context_missing")

    target =
      required_context_map!(semantic_context, :target_device, "device_approval_context_missing")

    assert_nil!(context_value(approver, :revoked_at), "device_approval_approver_inactive")

    assert_literal!(
      transcript["approving_owner_id"],
      context_value(approver, :id),
      "device_approval_approver_mismatch"
    )

    assert_literal!(
      transcript["approving_signing_key_id"],
      context_value(approver, :signing_key_id),
      "device_approval_signing_key_mismatch"
    )

    assert_literal!(
      transcript["target_device_id"],
      context_value(target, :id),
      "device_approval_target_mismatch"
    )

    assert_literal!(
      transcript["target_device_signing_key_id"],
      context_value(target, :signing_key_id),
      "device_approval_target_signing_key_mismatch"
    )
  end

  @spec validate_recovery_approval!(map(), binary(), binary(), binary()) :: :ok
  def validate_recovery_approval!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    assert_binary!(transcript["approval_signature_surface"], "approval_signature_surface_invalid")

    assert_binary!(
      transcript["recovery_session_transcript_hash"],
      "recovery_session_transcript_hash_invalid"
    )
  end

  @spec validate_recovery_approval!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_recovery_approval!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_recovery_approval!(transcript, signing_purpose, owner_kind, owner_id)

    recovery =
      required_context_map!(
        semantic_context,
        :recovery_session,
        "recovery_approval_context_missing"
      )

    target =
      required_context_map!(semantic_context, :target_device, "recovery_approval_context_missing")

    assert_literal!(
      transcript["recovery_session_transcript_hash"],
      context_value(recovery, :recovery_session_transcript_hash),
      "recovery_approval_session_mismatch"
    )

    assert_literal!(
      transcript["recovery_capability_hash"],
      context_value(recovery, :recovery_capability_hash),
      "recovery_approval_capability_mismatch"
    )

    assert_literal!(
      transcript["pending_registration_binding_hash"],
      context_value(recovery, :pending_registration_binding_hash),
      "recovery_approval_pending_registration_mismatch"
    )

    assert_literal!(
      transcript["target_device_id"],
      context_value(target, :id),
      "recovery_approval_target_mismatch"
    )
  end

  @spec validate_genesis_device_bootstrap!(map(), binary(), binary(), binary()) :: :ok
  def validate_genesis_device_bootstrap!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    assert_binary!(transcript["subject_protocol"], "subject_protocol_invalid")
    Core.assert_map!(transcript["bootstrap_authority"], "bootstrap_authority_invalid")
  end

  @spec validate_genesis_device_bootstrap!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_genesis_device_bootstrap!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_genesis_device_bootstrap!(transcript, signing_purpose, owner_kind, owner_id)

    target =
      required_context_map!(
        semantic_context,
        :target_device,
        "genesis_device_bootstrap_context_missing"
      )

    assert_literal!(
      context_value(semantic_context, :active_device_records?),
      false,
      "genesis_device_bootstrap_existing_device"
    )

    assert_literal!(
      transcript["user_id"],
      context_value(target, :user_id),
      "genesis_device_bootstrap_user_mismatch"
    )

    assert_literal!(
      transcript["device_id"],
      context_value(target, :id),
      "genesis_device_bootstrap_device_mismatch"
    )

    assert_literal!(
      transcript["identity_signing_key_id"],
      context_value(semantic_context, :identity_signing_key_id),
      "genesis_device_bootstrap_identity_mismatch"
    )
  end

  @spec validate_document_admission!(map(), binary(), binary(), binary()) :: :ok
  def validate_document_admission!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["authority_boundary"], "authority_boundary_invalid")
    Core.assert_map!(transcript["actor"], "actor_invalid")
  end

  @spec validate_document_admission!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_document_admission!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_document_admission!(transcript, signing_purpose, owner_kind, owner_id)

    document =
      required_context_map!(semantic_context, :document, "document_semantic_context_missing")

    session =
      required_context_map!(semantic_context, :session, "document_semantic_context_missing")

    actor = transcript["actor"]
    public_data = transcript["public_data"]

    assert_literal!(
      transcript["document_id"],
      context_value(document, :id),
      "document_admission_document_mismatch"
    )

    assert_literal!(
      actor["key_scope_id"],
      context_value(document, :workspace_id),
      "document_admission_workspace_mismatch"
    )

    assert_literal!(
      public_data["docId"],
      context_value(document, :id),
      "document_admission_public_data_document_mismatch"
    )

    assert_literal!(
      actor["signing_key_id"],
      context_value(session, :signing_key_id),
      "document_admission_signing_key_mismatch"
    )
  end

  @spec validate_key_directory_checkpoint!(map(), binary(), binary(), binary()) :: :ok
  def validate_key_directory_checkpoint!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["scope"], "checkpoint_scope_invalid")
    Core.assert_map!(transcript["signer"], "checkpoint_signer_invalid")
    Core.assert_map!(transcript["authority_boundary"], "checkpoint_authority_boundary_invalid")
    Core.assert_map!(transcript["suite_policy"], "checkpoint_suite_policy_invalid")
  end

  @spec validate_key_directory_checkpoint!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_key_directory_checkpoint!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_key_directory_checkpoint!(transcript, signing_purpose, owner_kind, owner_id)

    checkpoint_payload =
      required_context_map!(
        semantic_context,
        :checkpoint_payload,
        "key_directory_checkpoint_semantic_context_missing"
      )

    assert_hash_of!(
      transcript["subject_hash"],
      checkpoint_payload,
      "key_directory_checkpoint_subject_hash_mismatch"
    )

    scope = transcript["scope"]

    covered_head =
      required_map!(checkpoint_payload["covered_event_head"], "checkpoint_head_invalid")

    assert_literal!(
      scope["scope_kind"],
      checkpoint_payload["scope_kind"],
      "key_directory_checkpoint_scope_mismatch"
    )

    assert_literal!(
      scope["scope_id"],
      checkpoint_payload["scope_id"],
      "key_directory_checkpoint_scope_mismatch"
    )

    assert_literal!(
      scope["checkpoint_sequence"],
      checkpoint_payload["sequence"],
      "key_directory_checkpoint_sequence_mismatch"
    )

    assert_literal!(
      scope["covered_event_head_sequence"],
      covered_head["head_sequence"],
      "key_directory_checkpoint_head_mismatch"
    )

    assert_literal!(
      scope["covered_event_head_hash"],
      covered_head["head_hash"],
      "key_directory_checkpoint_head_mismatch"
    )
  end

  @spec validate_pq_wrap!(map(), binary(), binary(), binary()) :: :ok
  def validate_pq_wrap!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["actor"], "actor_invalid")
    Core.assert_map!(transcript["authority_boundary"], "authority_boundary_invalid")
    Core.assert_map!(transcript["subject_hashes"], "subject_hashes_invalid")
  end

  @spec validate_workspace_pin_bootstrap!(map(), binary(), binary(), binary()) :: :ok
  def validate_workspace_pin_bootstrap!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["actor"], "actor_invalid")
    Core.assert_map!(transcript["authority_boundary"], "authority_boundary_invalid")
    Core.assert_map!(transcript["suite_policy"], "suite_policy_invalid")
  end

  @spec validate_workspace_pin_bootstrap!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_workspace_pin_bootstrap!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_workspace_pin_bootstrap!(transcript, signing_purpose, owner_kind, owner_id)

    bootstrap =
      required_context_map!(
        semantic_context,
        :bootstrap,
        "workspace_pin_bootstrap_context_missing"
      )

    assert_hash_of!(
      transcript["subject_hash"],
      bootstrap,
      "workspace_pin_bootstrap_subject_hash_mismatch"
    )

    assert_literal!(
      transcript["actor"],
      bootstrap["issuer"],
      "workspace_pin_bootstrap_issuer_mismatch"
    )
  end

  @spec validate_key_directory_event!(map(), binary(), binary(), binary()) :: :ok
  def validate_key_directory_event!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["event"], "event_invalid")
  end

  @spec validate_key_directory_event!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_key_directory_event!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_key_directory_event!(transcript, signing_purpose, owner_kind, owner_id)

    event_payload =
      required_context_map!(
        semantic_context,
        :event_payload,
        "key_directory_event_semantic_context_missing"
      )

    checkpoint_payload =
      required_context_map!(
        semantic_context,
        :checkpoint_payload,
        "key_directory_event_semantic_context_missing"
      )

    assert_hash_of!(
      transcript["subject_hash"],
      event_payload,
      "key_directory_event_subject_hash_mismatch"
    )

    event = transcript["event"]

    assert_literal!(
      event["event_type"],
      event_payload["event_type"],
      "key_directory_event_type_mismatch"
    )

    assert_literal!(
      event["scope_kind"],
      event_payload["scope_kind"],
      "key_directory_event_scope_mismatch"
    )

    assert_literal!(
      event["scope_id"],
      event_payload["scope_id"],
      "key_directory_event_scope_mismatch"
    )

    assert_literal!(
      event["sequence"],
      event_payload["sequence"],
      "key_directory_event_sequence_mismatch"
    )

    unless context_value(semantic_context, :event_semantics_verified) == true do
      Replay.assert_event_semantics_against_checkpoint!(event_payload, checkpoint_payload)
    end

    :ok
  end

  @spec validate_share_capability_authorization!(map(), binary(), binary(), binary()) :: :ok
  def validate_share_capability_authorization!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["authorization"], "authorization_invalid")
    Core.assert_map!(transcript["share_state"], "share_state_invalid")
  end

  @spec validate_share_capability_authorization!(map(), binary(), binary(), binary(), map()) ::
          :ok
  def validate_share_capability_authorization!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok =
      validate_share_capability_authorization!(transcript, signing_purpose, owner_kind, owner_id)

    share = required_context_map!(semantic_context, :share, "share_capability_context_missing")

    assert_share_state!(
      transcript["share_state"],
      share,
      "share_capability_state_mismatch"
    )

    assert_literal!(
      transcript["authorization"]["token_hash"],
      context_value(share, :token_hash),
      "share_capability_token_hash_mismatch"
    )

    assert_literal!(
      transcript["authorization"]["workspace_pin_bootstrap_hash"],
      context_value(share, :authenticated_workspace_pin_bootstrap_hash),
      "share_capability_pin_bootstrap_mismatch"
    )
  end

  @spec validate_pop!(map(), binary(), binary(), binary()) :: :ok
  def validate_pop!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    variant = transcript["surface_variant"]

    unless transcript["pop_variant"] == variant,
      do: raise(ArgumentError, "pop_variant_mismatch")

    expected_transport =
      if String.starts_with?(variant, "channel_"), do: "phoenix_channel", else: "http"

    unless transcript["transport"] == expected_transport,
      do: raise(ArgumentError, "pop_transport_mismatch")

    :ok
  end

  @spec validate_pop!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_pop!(transcript, signing_purpose, owner_kind, owner_id, semantic_context) do
    :ok = validate_pop!(transcript, signing_purpose, owner_kind, owner_id)

    device = required_context_map!(semantic_context, :device, "pop_context_missing")
    session = required_context_map!(semantic_context, :session, "pop_context_missing")

    assert_nil!(context_value(device, :revoked_at), "pop_device_inactive")

    assert_literal!(
      transcript["challenge"],
      context_value(semantic_context, :challenge),
      "pop_challenge_mismatch"
    )

    assert_literal!(
      transcript["session"]["session_id_hash"],
      context_value(session, :session_id_hash),
      "pop_session_mismatch"
    )

    assert_pop_actor_matches_context!(transcript, device, semantic_context)
  end

  @spec validate_ake_prekey!(map(), binary(), binary(), binary()) :: :ok
  def validate_ake_prekey!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["responder"], "responder_invalid")
    Core.assert_map!(transcript["freshness"], "freshness_invalid")
  end

  @spec validate_ake_commitment!(map(), binary(), binary(), binary()) :: :ok
  def validate_ake_commitment!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["ake_inputs"], "ake_inputs_invalid")
    Core.assert_map!(transcript["binding"], "binding_invalid")
    Core.assert_map!(transcript["initiator"], "initiator_invalid")
    Core.assert_map!(transcript["suite"], "suite_invalid")
  end

  @spec validate_initial_key_delivery!(map(), binary(), binary(), binary()) :: :ok
  def validate_initial_key_delivery!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["delivery"], "delivery_invalid")
    Core.assert_map!(transcript["authority"], "authority_invalid")
  end

  @spec validate_initial_key_delivery!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_initial_key_delivery!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_initial_key_delivery!(transcript, signing_purpose, owner_kind, owner_id)

    signing_body =
      required_context_map!(
        semantic_context,
        :delivery_signing_body,
        "initial_key_delivery_semantic_context_missing"
      )

    assert_hash_of!(
      transcript["subject_hash"],
      signing_body,
      "initial_key_delivery_subject_hash_mismatch"
    )

    assert_literal!(
      transcript["authority"],
      required_context_map!(
        semantic_context,
        :authority,
        "initial_key_delivery_authority_missing"
      ),
      "initial_key_delivery_authority_mismatch"
    )
  end

  @spec validate_recipient_bound_authorization!(map(), binary(), binary(), binary()) :: :ok
  def validate_recipient_bound_authorization!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["actor"], "actor_invalid")
    Core.assert_map!(transcript["authority_boundary"], "authority_boundary_invalid")
    Core.assert_map!(transcript["freshness"], "freshness_invalid")
    Core.assert_map!(transcript["recipient"], "recipient_invalid")
  end

  @spec validate_pin_gossip!(map(), binary(), binary(), binary()) :: :ok
  def validate_pin_gossip!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["pin_gossip"], "pin_gossip_invalid")
  end

  @spec validate_recovery_authorization_proof!(map(), binary(), binary(), binary()) :: :ok
  def validate_recovery_authorization_proof!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)

    assert_in!(
      transcript["subject_protocol"],
      ["refmd.recovery-authorization-proof"],
      "subject_protocol_invalid"
    )

    assert_binary!(transcript["server_challenge_hash"], "server_challenge_hash_invalid")

    assert_binary!(
      transcript["pending_registration_binding_hash"],
      "pending_registration_binding_hash_invalid"
    )

    assert_binary!(
      transcript["recovery_authorization_key_id"],
      "recovery_authorization_key_id_invalid"
    )

    assert_binary!(transcript["recipient_device_id"], "recipient_device_id_invalid")
  end

  @spec validate_share_participant_device_authorization!(map(), binary(), binary(), binary()) ::
          :ok
  def validate_share_participant_device_authorization!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id
      ) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    assert_binary!(transcript["share_id"], "share_id_invalid")
    assert_binary!(transcript["share_session_id"], "share_session_id_invalid")

    assert_binary!(
      transcript["share_participant_principal_id"],
      "share_participant_principal_id_invalid"
    )

    assert_binary!(
      transcript["share_participant_device_id"],
      "share_participant_device_id_invalid"
    )

    assert_binary!(transcript["participant_signing_key_id"], "participant_signing_key_id_invalid")

    assert_binary!(
      transcript["participant_encryption_key_id"],
      "participant_encryption_key_id_invalid"
    )

    assert_binary!(transcript["capability_context_hash"], "capability_context_hash_invalid")
    assert_binary!(transcript["share_created_event_hash"], "share_created_event_hash_invalid")

    assert_binary!(
      transcript["latest_bootstrap_event_hash"],
      "latest_bootstrap_event_hash_invalid"
    )

    assert_binary!(transcript["scope_id"], "scope_id_invalid")
    assert_in!(transcript["scope_kind"], ["document", "folder"], "scope_kind_invalid")
    assert_in!(transcript["permission"], ["view", "edit"], "permission_invalid")

    if transcript["share_participant_device_id"] != owner_id do
      raise ArgumentError, "share_participant_device_id_owner_mismatch"
    end

    :ok
  end

  @spec validate_share_participant_device_authorization!(
          map(),
          binary(),
          binary(),
          binary(),
          map()
        ) :: :ok
  def validate_share_participant_device_authorization!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok =
      validate_share_participant_device_authorization!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id
      )

    share =
      required_context_map!(
        semantic_context,
        :share,
        "share_participant_authorization_context_missing"
      )

    participant =
      required_context_map!(
        semantic_context,
        :participant,
        "share_participant_authorization_context_missing"
      )

    assert_share_participant_state!(
      transcript,
      share,
      "share_participant_authorization_state_mismatch"
    )

    assert_literal!(
      transcript["share_participant_principal_id"],
      context_value(participant, :principal_id),
      "share_participant_principal_mismatch"
    )

    assert_literal!(
      transcript["share_session_id"],
      context_value(participant, :session_id),
      "share_participant_session_mismatch"
    )
  end

  @spec validate_recovery_session!(map(), binary(), binary(), binary()) :: :ok
  def validate_recovery_session!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    assert_binary!(transcript["server_challenge_hash"], "server_challenge_hash_invalid")
    assert_binary!(transcript["recovery_capability_hash"], "recovery_capability_hash_invalid")

    assert_binary!(
      transcript["pending_registration_binding_hash"],
      "pending_registration_binding_hash_invalid"
    )
  end

  @spec validate_recovery_session!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_recovery_session!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_recovery_session!(transcript, signing_purpose, owner_kind, owner_id)

    recovery =
      required_context_map!(
        semantic_context,
        :recovery_session,
        "recovery_session_context_missing"
      )

    pin =
      required_context_map!(semantic_context, :candidate_pin, "recovery_session_context_missing")

    pending =
      required_context_map!(
        semantic_context,
        :pending_registration,
        "recovery_session_context_missing"
      )

    assert_literal!(
      transcript["server_challenge_hash"],
      context_value(recovery, :server_challenge_hash),
      "recovery_session_challenge_mismatch"
    )

    assert_literal!(
      transcript["pending_registration_id"],
      context_value(pending, :id),
      "recovery_session_pending_registration_mismatch"
    )

    assert_literal!(
      transcript["candidate_user_checkpoint_sequence"],
      context_value(pin, :checkpoint_sequence),
      "recovery_session_checkpoint_mismatch"
    )

    assert_literal!(
      transcript["candidate_user_checkpoint_hash"],
      context_value(pin, :checkpoint_hash),
      "recovery_session_checkpoint_mismatch"
    )

    assert_literal!(
      transcript["candidate_user_event_head_sequence"],
      context_value(pin, :event_head_sequence),
      "recovery_session_event_head_mismatch"
    )

    assert_literal!(
      transcript["candidate_user_event_head_hash"],
      context_value(pin, :event_head_hash),
      "recovery_session_event_head_mismatch"
    )
  end

  @spec validate_key_deletion!(map(), binary(), binary(), binary()) :: :ok
  def validate_key_deletion!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["actor"], "actor_invalid")
    Core.assert_map!(transcript["authority_boundary"], "authority_boundary_invalid")
  end

  @spec validate_key_deletion!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_key_deletion!(transcript, signing_purpose, owner_kind, owner_id, semantic_context) do
    :ok = validate_key_deletion!(transcript, signing_purpose, owner_kind, owner_id)

    actor = transcript["actor"]
    authority = transcript["authority_boundary"]

    signer =
      required_context_map!(semantic_context, :signer, "key_deletion_context_missing")

    deletion =
      required_context_map!(semantic_context, :deletion, "key_deletion_context_missing")

    assert_nil!(context_value(signer, :revoked_at), "key_deletion_signer_inactive")

    assert_literal!(
      actor["device_id"],
      context_value(signer, :id),
      "key_deletion_signer_mismatch"
    )

    assert_literal!(
      actor["signing_key_id"],
      context_value(signer, :signing_key_id),
      "key_deletion_signing_key_mismatch"
    )

    assert_literal!(
      authority["scope_id"],
      context_value(deletion, :scope_id),
      "key_deletion_scope_mismatch"
    )

    assert_literal!(
      authority["old_key_version"],
      context_value(deletion, :old_key_version),
      "key_deletion_old_key_version_mismatch"
    )

    assert_literal!(
      authority["rotation_completed_event_hash"],
      context_value(deletion, :rotation_completed_event_hash),
      "key_deletion_rotation_completed_mismatch"
    )

    assert_literal!(
      authority["deleted_secret_ids_hash"],
      context_value(deletion, :deleted_secret_ids_hash),
      "key_deletion_deleted_secret_ids_mismatch"
    )
  end

  @spec validate_device_revocation!(map(), binary(), binary(), binary()) :: :ok
  def validate_device_revocation!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["actor"], "actor_invalid")
    Core.assert_map!(transcript["authority_boundary"], "authority_boundary_invalid")
    Core.assert_map!(transcript["revocation"], "revocation_invalid")
  end

  @spec validate_device_revocation!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_device_revocation!(
        transcript,
        signing_purpose,
        owner_kind,
        owner_id,
        semantic_context
      ) do
    :ok = validate_device_revocation!(transcript, signing_purpose, owner_kind, owner_id)

    signer =
      required_context_map!(semantic_context, :signer, "device_revocation_context_missing")

    target =
      required_context_map!(semantic_context, :target_device, "device_revocation_context_missing")

    assert_nil!(context_value(signer, :revoked_at), "device_revocation_signer_inactive")

    assert_literal!(
      transcript["actor"]["device_id"],
      context_value(signer, :id),
      "device_revocation_signer_mismatch"
    )

    assert_literal!(
      transcript["actor"]["signing_key_id"],
      context_value(signer, :signing_key_id),
      "device_revocation_signing_key_mismatch"
    )

    assert_literal!(
      transcript["revocation"]["device_id"],
      context_value(target, :id),
      "device_revocation_target_mismatch"
    )
  end

  @spec validate_ephemeral!(map(), binary(), binary(), binary()) :: :ok
  def validate_ephemeral!(transcript, signing_purpose, owner_kind, owner_id) do
    :ok = validate_transcript!(transcript, signing_purpose, owner_kind, owner_id)
    Core.assert_map!(transcript["actor"], "actor_invalid")
    Core.assert_map!(transcript["session"], "session_invalid")
  end

  @spec validate_ephemeral!(map(), binary(), binary(), binary(), map()) :: :ok
  def validate_ephemeral!(transcript, signing_purpose, owner_kind, owner_id, semantic_context) do
    :ok = validate_ephemeral!(transcript, signing_purpose, owner_kind, owner_id)

    document =
      required_context_map!(semantic_context, :document, "ephemeral_semantic_context_missing")

    session =
      required_context_map!(semantic_context, :session, "ephemeral_semantic_context_missing")

    workspace_event_head =
      required_context_map!(
        semantic_context,
        :workspace_event_head,
        "ephemeral_workspace_head_context_missing"
      )

    actor = transcript["actor"]
    transcript_session = transcript["session"]
    boundary = required_map!(transcript["authority_boundary"], "authority_boundary_invalid")

    assert_literal!(
      actor["signing_key_id"],
      context_value(session, :signing_key_id),
      "ephemeral_signing_key_mismatch"
    )

    assert_literal!(
      actor["key_scope_id"],
      context_value(document, :workspace_id),
      "ephemeral_workspace_mismatch"
    )

    assert_literal!(
      transcript_session["workspace_id"],
      context_value(document, :workspace_id),
      "ephemeral_workspace_mismatch"
    )

    assert_literal!(
      transcript_session["document_id"],
      context_value(document, :id),
      "ephemeral_document_mismatch"
    )

    assert_literal!(
      boundary["workspace_event_head_sequence"],
      context_value(workspace_event_head, :sequence),
      "ephemeral_workspace_head_mismatch"
    )

    assert_literal!(
      boundary["workspace_event_head_hash"],
      context_value(workspace_event_head, :hash),
      "ephemeral_workspace_head_mismatch"
    )

    assert_literal!(
      boundary["expires_event_sequence"],
      context_value(workspace_event_head, :sequence) + 1,
      "ephemeral_workspace_head_mismatch"
    )
  end

  defp assert_binary!(value, _message) when is_binary(value) and byte_size(value) > 0,
    do: :ok

  defp assert_binary!(_, message), do: raise(ArgumentError, message)

  defp assert_in!(value, allowed, message) do
    if value in allowed,
      do: :ok,
      else: raise(ArgumentError, message)
  end

  defp required_context_map!(context, key, message) when is_map(context) do
    case Map.get(context, key) || Map.get(context, to_string(key)) do
      value when is_map(value) -> value
      _ -> raise ArgumentError, message
    end
  end

  defp required_map!(value, _message) when is_map(value), do: value
  defp required_map!(_value, message), do: raise(ArgumentError, message)

  defp context_value(map, key) when is_map(map) do
    if Map.has_key?(map, key), do: Map.get(map, key), else: Map.get(map, to_string(key))
  end

  defp assert_literal!(actual, expected, _message) when actual == expected, do: :ok
  defp assert_literal!(_actual, _expected, message), do: raise(ArgumentError, message)

  defp assert_nil!(nil, _message), do: :ok
  defp assert_nil!(_value, message), do: raise(ArgumentError, message)

  defp assert_pop_actor_matches_context!(
         %{"owner_kind" => "device"} = transcript,
         device,
         context
       ) do
    actor = transcript["actor"]

    assert_literal!(actor["device_id"], context_value(device, :id), "pop_actor_mismatch")
    assert_literal!(actor["user_id"], context_value(context, :user_id), "pop_actor_mismatch")

    assert_literal!(
      actor["signing_key_id"],
      context_value(device, :signing_key_id),
      "pop_signing_key_mismatch"
    )
  end

  defp assert_pop_actor_matches_context!(
         %{"owner_kind" => "share_participant_device"} = transcript,
         device,
         context
       ) do
    actor = transcript["actor"]

    assert_literal!(
      actor["share_participant_device_id"],
      context_value(device, :id),
      "pop_actor_mismatch"
    )

    assert_literal!(
      actor["share_participant_principal_id"],
      context_value(context, :principal_id),
      "pop_actor_mismatch"
    )

    assert_literal!(actor["share_id"], context_value(context, :share_id), "pop_actor_mismatch")

    assert_literal!(
      actor["signing_key_id"],
      context_value(device, :signing_key_id),
      "pop_signing_key_mismatch"
    )
  end

  defp assert_hash_of!(actual_hash, preimage, message)
       when is_binary(actual_hash) and is_map(preimage) do
    assert_literal!(actual_hash, Hash.blake3_base64url(JCS.canonical_bytes!(preimage)), message)
  end

  defp assert_hash_of!(_, _, message), do: raise(ArgumentError, message)

  defp assert_share_state!(state, share, message) when is_map(state) and is_map(share) do
    checks = [
      state["share_id"] == context_value(share, :id),
      state["scope_kind"] == context_value(share, :scope),
      state["scope_id"] == context_value(share, :document_id),
      state["permission"] == context_value(share, :permission),
      state["created_event_hash"] == context_value(share, :created_event_hash),
      state["latest_bootstrap_event_hash"] == context_value(share, :latest_bootstrap_event_hash),
      state["capability_context_hash"] == context_value(share, :capability_context_hash)
    ]

    if Enum.all?(checks), do: :ok, else: raise(ArgumentError, message)
  end

  defp assert_share_state!(_, _, message), do: raise(ArgumentError, message)

  defp assert_share_participant_state!(state, share, message)
       when is_map(state) and is_map(share) do
    checks = [
      state["share_id"] == context_value(share, :id),
      state["scope_kind"] == context_value(share, :scope),
      state["scope_id"] == context_value(share, :document_id),
      state["permission"] == context_value(share, :permission),
      state["share_created_event_hash"] == context_value(share, :created_event_hash),
      state["latest_bootstrap_event_hash"] == context_value(share, :latest_bootstrap_event_hash),
      state["capability_context_hash"] == context_value(share, :capability_context_hash)
    ]

    if Enum.all?(checks), do: :ok, else: raise(ArgumentError, message)
  end

  defp assert_share_participant_state!(_, _, message), do: raise(ArgumentError, message)
end
