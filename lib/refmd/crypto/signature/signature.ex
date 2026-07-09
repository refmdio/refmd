defmodule RefMD.Crypto.Signature do
  @moduledoc false

  alias RefMD.Crypto.Encoding
  alias RefMD.Crypto.Hash
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.Native
  alias RefMD.Crypto.SigningSurface

  alias RefMD.Crypto.Signature.{
    ApprovalProof,
    Collaboration,
    Device,
    KeyDirectory,
    Recovery,
    Share
  }

  @protocol_version 1
  @suite_rank 1000
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"

  @signature_protocol "refmd.hybrid-signature"
  @public_key_material_protocol "refmd.hybrid-signing-key-material"
  @mldsa_context_prefix "RefMD:v2:"

  @ed25519_public_bytes 32
  @ed25519_signature_bytes 64
  @mldsa65_public_bytes 1952
  @mldsa65_signature_bytes 3309

  @allowed_owner_kind_values MapSet.new([
                               "identity",
                               "device",
                               "invitation_redeem_authority",
                               "share_capability",
                               "share_participant_device"
                             ])

  @public_material_keys Enum.sort([
                          "ed25519_public",
                          "mldsa65_public",
                          "owner_id",
                          "owner_kind",
                          "protocol",
                          "suite_id",
                          "suite_rank",
                          "version"
                        ])
  @signature_keys Enum.sort([
                    "ed25519",
                    "mldsa65",
                    "protocol",
                    "signing_key_id",
                    "suite_id",
                    "suite_rank",
                    "transcript_hash",
                    "version"
                  ])

  @semantic_error_reasons MapSet.new([
                            :actor_invalid,
                            :ake_inputs_invalid,
                            :approval_proof_invalid,
                            :approval_signature_surface_invalid,
                            :approving_device_key_directory_proof_hash_invalid,
                            :authority_boundary_invalid,
                            :authority_invalid,
                            :authorization_invalid,
                            :binding_invalid,
                            :bootstrap_authority_invalid,
                            :capability_context_hash_invalid,
                            :checkpoint_authority_boundary_invalid,
                            :checkpoint_head_invalid,
                            :checkpoint_scope_invalid,
                            :checkpoint_signer_invalid,
                            :checkpoint_suite_policy_invalid,
                            :delivery_invalid,
                            :device_approval_approver_inactive,
                            :device_approval_approver_mismatch,
                            :device_approval_context_missing,
                            :device_approval_signing_key_mismatch,
                            :device_approval_target_mismatch,
                            :device_approval_target_signing_key_mismatch,
                            :device_approval_transcript_invalid,
                            :device_key_deletion_proof_transcript_invalid,
                            :device_revocation_context_missing,
                            :device_revocation_signer_inactive,
                            :device_revocation_signer_mismatch,
                            :device_revocation_signing_key_mismatch,
                            :device_revocation_target_mismatch,
                            :device_revocation_transcript_invalid,
                            :document_admission_document_mismatch,
                            :document_admission_public_data_document_mismatch,
                            :document_admission_signing_key_mismatch,
                            :document_admission_workspace_mismatch,
                            :document_semantic_context_missing,
                            :document_snapshot_transcript_invalid,
                            :document_update_transcript_invalid,
                            :ed25519_private_public_mismatch,
                            :ed25519_signature_invalid,
                            :ephemeral_document_mismatch,
                            :ephemeral_semantic_context_missing,
                            :ephemeral_signing_key_mismatch,
                            :ephemeral_workspace_head_context_missing,
                            :ephemeral_workspace_head_mismatch,
                            :ephemeral_workspace_mismatch,
                            :editor_ephemeral_session_actor_invalid,
                            :editor_ephemeral_session_transcript_invalid,
                            :editor_ephemeral_transcript_invalid,
                            :event_invalid,
                            :freshness_invalid,
                            :genesis_device_bootstrap_context_missing,
                            :genesis_device_bootstrap_device_mismatch,
                            :genesis_device_bootstrap_existing_device,
                            :genesis_device_bootstrap_identity_mismatch,
                            :genesis_device_bootstrap_transcript_invalid,
                            :genesis_device_bootstrap_user_mismatch,
                            :initial_key_delivery_authority_mismatch,
                            :initial_key_delivery_authority_missing,
                            :initial_key_delivery_semantic_context_missing,
                            :initial_key_delivery_subject_hash_mismatch,
                            :initial_key_delivery_transcript_invalid,
                            :initiator_ake_commitment_transcript_invalid,
                            :initiator_invalid,
                            :key_deletion_context_missing,
                            :key_deletion_deleted_secret_ids_mismatch,
                            :key_deletion_old_key_version_mismatch,
                            :key_deletion_rotation_completed_mismatch,
                            :key_deletion_scope_mismatch,
                            :key_deletion_signer_inactive,
                            :key_deletion_signer_mismatch,
                            :key_deletion_signing_key_mismatch,
                            :key_directory_checkpoint_authority_boundary_invalid,
                            :key_directory_checkpoint_head_mismatch,
                            :key_directory_checkpoint_scope_mismatch,
                            :key_directory_checkpoint_semantic_context_missing,
                            :key_directory_checkpoint_sequence_mismatch,
                            :key_directory_checkpoint_subject_hash_mismatch,
                            :key_directory_checkpoint_transcript_invalid,
                            :key_directory_event_authority_boundary_invalid,
                            :key_directory_event_scope_mismatch,
                            :key_directory_event_semantic_context_missing,
                            :key_directory_event_sequence_mismatch,
                            :key_directory_event_subject_hash_mismatch,
                            :key_directory_event_transcript_invalid,
                            :key_directory_event_type_mismatch,
                            :key_directory_transcript_required_field_missing,
                            :key_directory_transcript_required_map_missing,
                            :latest_bootstrap_event_hash_invalid,
                            :mldsa65_private_public_mismatch,
                            :mldsa65_signature_invalid,
                            :mldsa_context_too_long,
                            :owner_exact_schema_missing,
                            :owner_id_invalid,
                            :owner_id_mismatch,
                            :owner_kind_invalid,
                            :owner_kind_mismatch,
                            :participant_encryption_key_id_invalid,
                            :participant_signing_key_id_invalid,
                            :pending_registration_binding_hash_invalid,
                            :permission_invalid,
                            :pin_gossip_invalid,
                            :pin_gossip_statement_transcript_invalid,
                            :plugin_bundle_approval_actor_invalid,
                            :plugin_bundle_approval_actor_mismatch,
                            :plugin_bundle_approval_context_missing,
                            :plugin_bundle_approval_signing_key_mismatch,
                            :plugin_bundle_approval_subject_hash_mismatch,
                            :plugin_bundle_approval_subject_invalid,
                            :plugin_bundle_approval_subject_mismatch,
                            :plugin_bundle_approval_subject_protocol_invalid,
                            :plugin_bundle_approval_transcript_invalid,
                            :plugin_consent_event_actor_invalid,
                            :plugin_consent_event_actor_mismatch,
                            :plugin_consent_event_context_missing,
                            :plugin_consent_event_signing_key_mismatch,
                            :plugin_consent_event_subject_hash_mismatch,
                            :plugin_consent_event_subject_invalid,
                            :plugin_consent_event_subject_mismatch,
                            :plugin_consent_event_subject_protocol_invalid,
                            :plugin_consent_event_transcript_invalid,
                            :plugin_network_proxy_request_actor_mismatch,
                            :plugin_network_proxy_request_context_missing,
                            :plugin_network_proxy_request_endpoint_invalid,
                            :plugin_network_proxy_request_proxy_invalid,
                            :plugin_network_proxy_request_runtime_invalid,
                            :plugin_network_proxy_request_subject_hash_mismatch,
                            :plugin_network_proxy_request_subject_invalid,
                            :plugin_network_proxy_request_subject_mismatch,
                            :plugin_network_proxy_request_subject_protocol_invalid,
                            :plugin_network_proxy_request_subject_version_invalid,
                            :plugin_network_proxy_request_target_invalid,
                            :plugin_network_proxy_request_transcript_invalid,
                            :plugin_transcript_invalid,
                            :rrp_actor_invalid,
                            :rrp_actor_mismatch,
                            :rrp_challenge_mismatch,
                            :rrp_context_missing,
                            :rrp_device_inactive,
                            :rrp_session_invalid,
                            :rrp_session_mismatch,
                            :rrp_signing_key_mismatch,
                            :rrp_transcript_invalid,
                            :rrp_transport_mismatch,
                            :rrp_variant_mismatch,
                            :pq_wrap_transcript_invalid,
                            :private_key_material_not_object,
                            :private_public_material_mismatch,
                            :private_public_owner_mismatch,
                            :public_key_material_not_object,
                            :recipient_bound_authorization_payload_invalid,
                            :recipient_bound_authorization_signing_key_mismatch,
                            :recipient_bound_authorization_transcript_invalid,
                            :recipient_device_id_invalid,
                            :recipient_invalid,
                            :recovery_approval_capability_mismatch,
                            :recovery_approval_context_missing,
                            :recovery_approval_pending_registration_mismatch,
                            :recovery_approval_session_mismatch,
                            :recovery_approval_target_mismatch,
                            :recovery_authorization_key_id_invalid,
                            :recovery_authorization_proof_transcript_invalid,
                            :recovery_capability_hash_invalid,
                            :recovery_device_approval_transcript_invalid,
                            :recovery_session_challenge_mismatch,
                            :recovery_session_checkpoint_mismatch,
                            :recovery_session_context_missing,
                            :recovery_session_event_head_mismatch,
                            :recovery_session_pending_registration_mismatch,
                            :recovery_session_transcript_hash_invalid,
                            :recovery_session_transcript_invalid,
                            :responder_invalid,
                            :responder_prekey_transcript_invalid,
                            :revocation_invalid,
                            :scope_id_invalid,
                            :scope_kind_invalid,
                            :server_challenge_hash_invalid,
                            :session_invalid,
                            :share_capability_context_missing,
                            :share_capability_pin_bootstrap_mismatch,
                            :share_capability_state_mismatch,
                            :share_capability_token_hash_mismatch,
                            :share_capability_authorization_transcript_invalid,
                            :share_created_event_hash_invalid,
                            :share_id_invalid,
                            :share_participant_authorization_context_missing,
                            :share_participant_authorization_state_mismatch,
                            :share_participant_device_authorization_transcript_invalid,
                            :share_participant_device_id_invalid,
                            :share_participant_device_id_owner_mismatch,
                            :share_participant_principal_id_invalid,
                            :share_participant_principal_mismatch,
                            :share_participant_session_mismatch,
                            :share_session_id_invalid,
                            :share_state_invalid,
                            :signature_input_invalid,
                            :signature_not_object,
                            :signature_protocol_version_invalid,
                            :signature_suite_invalid,
                            :signer_kind_invalid,
                            :signing_key_id_mismatch,
                            :signing_purpose_invalid,
                            :signing_purpose_mismatch,
                            :subject_hashes_invalid,
                            :subject_protocol_invalid,
                            :subject_version_invalid,
                            :suite_invalid,
                            :suite_policy_invalid,
                            :surface_id_mismatch,
                            :surface_variant_invalid,
                            :surface_variant_mismatch,
                            :transcript_hash_mismatch,
                            :transcript_owner_mismatch,
                            :unexpected_keys,
                            :workspace_pin_bootstrap_context_missing,
                            :workspace_pin_bootstrap_issuer_mismatch,
                            :workspace_pin_bootstrap_subject_hash_mismatch,
                            :workspace_pin_bootstrap_transcript_invalid
                          ])
  @semantic_error_reason_by_message Map.new(
                                      @semantic_error_reasons,
                                      &{Atom.to_string(&1), &1}
                                    )
  @key_directory_event_variants [
    "device_key_added",
    "encryption_key_revoked",
    "identity_key_added",
    "member_added",
    "member_role_changed",
    "member_removed",
    "document_snapshot_accepted",
    "document_update_accepted",
    "document_write_session_admitted",
    "old_key_deleted",
    "rotation_completed",
    "rotation_started",
    "share_created",
    "share_exclusion_changed",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_metadata_updated",
    "recipient_bound_delivery_admitted",
    "share_revoked",
    "workspace_invitation_created",
    "workspace_invitation_bootstrap_updated",
    "workspace_invitation_revoked",
    "workspace_invitation_redeemed",
    "guest_invitation_created",
    "guest_invitation_bootstrap_updated",
    "guest_invitation_revoked",
    "guest_invitation_redeemed",
    "guest_grant_revoked",
    "guest_device_revoked",
    "signing_key_revoked",
    "suite_policy_changed",
    "wrap_issued"
  ]

  def compute_signing_key_id!(public_key_material) when is_map(public_key_material) do
    assert_public_key_material!(public_key_material)
    Hash.blake3_base64url(JCS.canonical_bytes!(public_key_material))
  end

  def verify_hybrid_signature(signing_purpose, transcript, signature, public_key_material) do
    match?(
      :ok,
      verify_hybrid_signature_result(signing_purpose, transcript, signature, public_key_material)
    )
  end

  def verify_hybrid_signature(
        signing_purpose,
        transcript,
        signature,
        public_key_material,
        semantic_context
      ) do
    match?(
      :ok,
      verify_hybrid_signature_result(
        signing_purpose,
        transcript,
        signature,
        public_key_material,
        semantic_context
      )
    )
  end

  def verify_recovery_authorization_proof_signature(transcript, signature, public_key_material)
      when is_map(transcript) and is_map(signature) and is_map(public_key_material) do
    verify_hybrid_signature(
      "recovery_authorization_proof",
      transcript,
      signature,
      public_key_material
    )
  end

  def verify_recovery_authorization_proof_signature(_, _, _), do: false

  def verify_hybrid_signature_result(signing_purpose, transcript, signature, public_key_material)
      when is_binary(signing_purpose) and is_map(transcript) and is_map(signature) and
             is_map(public_key_material) do
    with :ok <- validate_signature_inputs_result(signing_purpose, signature, public_key_material),
         :ok <-
           verify_signature_components_result(
             signing_purpose,
             transcript,
             signature,
             public_key_material
           ) do
      validate_semantic_transcript_shape_result(
        transcript,
        signing_purpose,
        public_key_material["owner_kind"],
        public_key_material["owner_id"]
      )
    end
  end

  def verify_hybrid_signature_result(_, _, _, _), do: {:error, :invalid_signature}

  def verify_hybrid_signature_result(
        signing_purpose,
        transcript,
        signature,
        public_key_material,
        semantic_context
      )
      when is_binary(signing_purpose) and is_map(transcript) and is_map(signature) and
             is_map(public_key_material) and is_map(semantic_context) do
    with :ok <- validate_signature_inputs_result(signing_purpose, signature, public_key_material),
         :ok <-
           verify_signature_components_result(
             signing_purpose,
             transcript,
             signature,
             public_key_material
           ) do
      validate_semantic_transcript_result(
        transcript,
        signing_purpose,
        public_key_material["owner_kind"],
        public_key_material["owner_id"],
        semantic_context
      )
    end
  end

  def verify_hybrid_signature_result(_, _, _, _, _), do: {:error, :invalid_signature}

  def protocol_version, do: @protocol_version

  def suite_rank, do: @suite_rank

  def suite_id, do: @suite_id

  def key_directory_event_variants, do: @key_directory_event_variants

  defdelegate build_rrp_transcript!(
                variant,
                owner_kind,
                owner_id,
                actor,
                challenge,
                session
              ),
              to: Device

  defdelegate build_rrp_transcript!(
                variant,
                owner_kind,
                owner_id,
                actor,
                challenge,
                session,
                resource
              ),
              to: Device

  defdelegate build_genesis_device_bootstrap_transcript!(params), to: Device

  defdelegate build_device_approval_transcript!(
                user_id,
                approver_device_id,
                approved_device_id,
                approved_device_public_material,
                approved_device_hybrid_encryption_public_key_material,
                client_nonce,
                commitments
              ),
              to: Device

  defdelegate build_device_revocation_transcript!(
                user_id,
                actor_device_id,
                signing_key_id,
                revoked_device_id,
                revocation_mode,
                revoked_at_ms
              ),
              to: Device

  defdelegate build_key_directory_checkpoint_transcript!(
                variant,
                owner_kind,
                owner_id,
                checkpoint_payload,
                signer \\ nil
              ),
              to: KeyDirectory

  defdelegate build_key_directory_event_transcript!(
                event_type,
                owner_kind,
                owner_id,
                event_payload
              ),
              to: KeyDirectory

  defdelegate build_workspace_pin_bootstrap_transcript!(owner_device_id, workspace_id, bootstrap),
    to: KeyDirectory

  defdelegate build_pq_wrap_transcript!(
                owner_device_id,
                actor,
                authority_boundary,
                subject_hashes
              ),
              to: KeyDirectory

  defdelegate build_initial_key_delivery_transcript!(
                owner_device_id,
                variant,
                delivery_signing_body,
                sender,
                recipient,
                ake,
                delivery,
                authority
              ),
              to: KeyDirectory

  defdelegate build_initiator_ake_commitment_transcript!(
                owner_device_id,
                commitment_payload,
                initiator,
                ake_inputs,
                binding
              ),
              to: KeyDirectory

  defdelegate build_responder_prekey_transcript!(
                owner_device_id,
                prekey_payload,
                responder,
                freshness
              ),
              to: KeyDirectory

  defdelegate build_recipient_bound_authorization_transcript!(
                owner_id,
                actor_user_id,
                actor_device_id,
                signing_key_id,
                authorization_payload
              ),
              to: Share

  defdelegate build_share_capability_authorization_transcript!(params),
    to: Share

  defdelegate build_share_participant_device_authorization_transcript!(params),
    to: Share

  defdelegate build_recovery_device_approval_transcript!(params), to: Recovery
  defdelegate build_recovery_authorization_proof_transcript!(params), to: Recovery
  defdelegate build_recovery_session_transcript!(params), to: Recovery
  defdelegate build_device_key_deletion_proof_transcript!(payload, actor), to: Recovery

  defdelegate build_document_update_transcript!(params),
    to: Collaboration

  defdelegate build_document_snapshot_transcript!(params),
    to: Collaboration

  defdelegate build_editor_ephemeral_transcript!(params), to: Collaboration

  defdelegate build_editor_ephemeral_session_transcript!(params), to: Collaboration

  defdelegate build_pin_gossip_statement_transcript!(owner_device_id, pin_gossip),
    to: KeyDirectory

  defdelegate build_device_approval_proof!(
                approval_signature_surface,
                transcript,
                surface_details
              ),
              to: ApprovalProof,
              as: :build!

  defdelegate build_device_approval_proof!(
                approval_signature_surface,
                transcript,
                surface_details,
                proof_context
              ),
              to: ApprovalProof,
              as: :build!

  def assert_hybrid_signature!(signing_purpose, transcript, signature, public_key_material)
      when is_binary(signing_purpose) and is_map(transcript) and is_map(signature) and
             is_map(public_key_material) do
    case verify_hybrid_signature_result(
           signing_purpose,
           transcript,
           signature,
           public_key_material
         ) do
      :ok -> :ok
      {:error, reason} -> raise(ArgumentError, Atom.to_string(reason))
    end
  end

  def assert_hybrid_signature!(_, _, _, _), do: raise(ArgumentError, "signature_input_invalid")

  defp validate_signature_inputs_result(signing_purpose, signature, public_key_material) do
    assert_signing_purpose!(signing_purpose)
    assert_public_key_material!(public_key_material)
    assert_signature_shape!(signature)
    :ok
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp validate_semantic_transcript_result(
         transcript,
         signing_purpose,
         owner_kind,
         owner_id,
         semantic_context
       ) do
    validate_semantic_transcript!(
      transcript,
      signing_purpose,
      owner_kind,
      owner_id,
      semantic_context
    )
  rescue
    error in ArgumentError -> {:error, semantic_error_reason(error)}
    _ -> {:error, :invalid_signature_semantics}
  end

  defp validate_semantic_transcript_shape_result(
         transcript,
         signing_purpose,
         owner_kind,
         owner_id
       ) do
    validate_semantic_transcript_shape!(
      transcript,
      signing_purpose,
      owner_kind,
      owner_id
    )
  rescue
    error in ArgumentError -> {:error, semantic_error_reason(error)}
    _ -> {:error, :invalid_signature_semantics}
  end

  if Mix.env() == :test do
    @doc false
    def __test_semantic_error_reason__(message) when is_binary(message) do
      semantic_error_reason(%ArgumentError{message: message})
    end
  end

  defp semantic_error_reason(%ArgumentError{message: message}) when is_binary(message) do
    Map.get(@semantic_error_reason_by_message, message, :invalid_signature_semantics)
  end

  defp verify_signature_components_result(
         signing_purpose,
         transcript,
         signature,
         public_key_material
       ) do
    transcript_bytes = JCS.canonical_bytes!(transcript)
    expected_transcript_hash = Hash.blake3_base64url(transcript_bytes)

    unless constant_binary_equal?(signature["transcript_hash"], expected_transcript_hash),
      do: raise(ArgumentError, "transcript_hash_mismatch")

    expected_signing_key_id = compute_signing_key_id!(public_key_material)

    unless constant_binary_equal?(signature["signing_key_id"], expected_signing_key_id),
      do: raise(ArgumentError, "signing_key_id_mismatch")

    ed_public =
      Encoding.decode_base64url!(public_key_material["ed25519_public"], @ed25519_public_bytes)

    ml_public =
      Encoding.decode_base64url!(public_key_material["mldsa65_public"], @mldsa65_public_bytes)

    ed_signature = Encoding.decode_base64url!(signature["ed25519"], @ed25519_signature_bytes)
    ml_signature = Encoding.decode_base64url!(signature["mldsa65"], @mldsa65_signature_bytes)

    unless :crypto.verify(:eddsa, :none, transcript_bytes, ed_signature, [ed_public, :ed25519]),
      do: raise(ArgumentError, "ed25519_signature_invalid")

    unless Native.mldsa65_verify(
             transcript_bytes,
             mldsa_context!(signing_purpose),
             ml_signature,
             ml_public
           ),
           do: raise(ArgumentError, "mldsa65_signature_invalid")

    :ok
  rescue
    _ -> {:error, :invalid_signature}
  end

  if Mix.env() == :test do
    alias RefMD.TestCrypto

    def __test_sign_hybrid_signature__(
          signing_purpose,
          transcript,
          private_key_material,
          public_key_material
        )
        when is_binary(signing_purpose) and is_map(transcript) and is_map(private_key_material) and
               is_map(public_key_material) do
      assert_signing_purpose!(signing_purpose)
      assert_public_key_material!(public_key_material)
      assert_private_key_material!(private_key_material)

      validate_semantic_transcript_shape!(
        transcript,
        signing_purpose,
        private_key_material["owner_kind"],
        private_key_material["owner_id"]
      )

      unless private_key_material["owner_kind"] == public_key_material["owner_kind"] and
               private_key_material["owner_id"] == public_key_material["owner_id"],
             do: raise(ArgumentError, "private_public_owner_mismatch")

      unless public_key_material_from_private!(private_key_material) == public_key_material,
        do: raise(ArgumentError, "private_public_material_mismatch")

      transcript_bytes = JCS.canonical_bytes!(transcript)

      ed_private =
        Encoding.decode_base64url!(
          private_key_material["ed25519_private"],
          32
        )

      ml_private =
        Encoding.decode_base64url!(
          private_key_material["mldsa65_private"],
          4032
        )

      %{
        "protocol" => @signature_protocol,
        "version" => @protocol_version,
        "suite_id" => @suite_id,
        "suite_rank" => @suite_rank,
        "signing_key_id" => compute_signing_key_id!(public_key_material),
        "transcript_hash" => Hash.blake3_base64url(transcript_bytes),
        "ed25519" =>
          :crypto.sign(:eddsa, :none, transcript_bytes, [ed_private, :ed25519])
          |> Encoding.encode_base64url(),
        "mldsa65" =>
          TestCrypto.mldsa65_sign(
            transcript_bytes,
            mldsa_context!(signing_purpose),
            ml_private
          )
          |> Encoding.encode_base64url()
      }
    end

    def __test_sign_hybrid_signature__(_, _, _, _),
      do: raise(ArgumentError, "signature_input_invalid")
  end

  defp validate_semantic_transcript!(
         transcript,
         signing_purpose,
         owner_kind,
         owner_id,
         semantic_context
       ) do
    surface =
      SigningSurface.get_active!(signing_purpose, Map.fetch!(transcript, "surface_variant"))

    validator = SigningSurface.semantic_validator!(surface)

    args = [
      transcript,
      signing_purpose,
      owner_kind,
      owner_id
    ]

    if validator.arity == 5 do
      apply(validator.module, validator.function, args ++ [semantic_context])
    else
      apply(validator.module, validator.function, args)
    end
  end

  defp validate_semantic_transcript_shape!(transcript, signing_purpose, owner_kind, owner_id) do
    surface =
      SigningSurface.get_active!(signing_purpose, Map.fetch!(transcript, "surface_variant"))

    validator = SigningSurface.semantic_validator!(surface)

    apply(validator.module, validator.function, [
      transcript,
      signing_purpose,
      owner_kind,
      owner_id
    ])
  end

  def assert_public_key_material!(material) when is_map(material) do
    assert_exact_keys!(material, @public_material_keys)

    assert_literal!(
      material["protocol"],
      @public_key_material_protocol,
      "public_key_protocol_invalid"
    )

    assert_protocol_version!(material["version"])
    assert_owner_kind!(material["owner_kind"])
    assert_non_empty_string!(material["owner_id"], "owner_id_invalid")
    assert_suite_fields!(material["suite_id"], material["suite_rank"])
    Encoding.decode_base64url!(material["ed25519_public"], @ed25519_public_bytes)
    Encoding.decode_base64url!(material["mldsa65_public"], @mldsa65_public_bytes)
    :ok
  end

  def assert_public_key_material!(_), do: raise(ArgumentError, "public_key_material_not_object")

  if Mix.env() == :test do
    alias RefMD.TestCrypto

    def assert_private_key_material!(material) when is_map(material) do
      assert_exact_keys!(
        material,
        Enum.sort([
          "ed25519_private",
          "ed25519_public",
          "mldsa65_private",
          "mldsa65_public",
          "owner_id",
          "owner_kind",
          "protocol",
          "suite_id",
          "suite_rank",
          "version"
        ])
      )

      assert_literal!(
        material["protocol"],
        "refmd.hybrid-signing-private-key-material",
        "private_key_protocol_invalid"
      )

      assert_protocol_version!(material["version"])
      assert_owner_kind!(material["owner_kind"])
      assert_non_empty_string!(material["owner_id"], "owner_id_invalid")
      assert_suite_fields!(material["suite_id"], material["suite_rank"])

      ed_private = Encoding.decode_base64url!(material["ed25519_private"], 32)
      ed_public = Encoding.decode_base64url!(material["ed25519_public"], @ed25519_public_bytes)
      ml_private = Encoding.decode_base64url!(material["mldsa65_private"], 4032)
      ml_public = Encoding.decode_base64url!(material["mldsa65_public"], @mldsa65_public_bytes)

      {derived_ed_public, _} = :crypto.generate_key(:eddsa, :ed25519, ed_private)

      unless derived_ed_public == ed_public,
        do: raise(ArgumentError, "ed25519_private_public_mismatch")

      probe = "refmd-private-material-public-key-check"
      context = mldsa_context!("private_material_check")
      signature = TestCrypto.mldsa65_sign(probe, context, ml_private)

      unless Native.mldsa65_verify(probe, context, signature, ml_public),
        do: raise(ArgumentError, "mldsa65_private_public_mismatch")

      :ok
    end

    def assert_private_key_material!(_),
      do: raise(ArgumentError, "private_key_material_not_object")

    defp public_key_material_from_private!(material) do
      assert_private_key_material!(material)

      %{
        "protocol" => @public_key_material_protocol,
        "version" => @protocol_version,
        "owner_kind" => material["owner_kind"],
        "owner_id" => material["owner_id"],
        "ed25519_public" => material["ed25519_public"],
        "mldsa65_public" => material["mldsa65_public"],
        "suite_id" => @suite_id,
        "suite_rank" => @suite_rank
      }
    end
  end

  def assert_hybrid_signature_shape!(signature) when is_map(signature),
    do: assert_signature_shape!(signature)

  def assert_hybrid_signature_shape!(_), do: raise(ArgumentError, "signature_not_object")

  defp assert_signature_shape!(signature) when is_map(signature) do
    assert_exact_keys!(signature, @signature_keys)
    assert_literal!(signature["protocol"], @signature_protocol, "signature_protocol_invalid")
    assert_protocol_version!(signature["version"])
    assert_suite_fields!(signature["suite_id"], signature["suite_rank"])
    Hash.assert_blake3_base64url!(signature["signing_key_id"])
    Hash.assert_blake3_base64url!(signature["transcript_hash"])
    Encoding.decode_base64url!(signature["ed25519"], @ed25519_signature_bytes)
    Encoding.decode_base64url!(signature["mldsa65"], @mldsa65_signature_bytes)
    :ok
  end

  defp assert_exact_keys!(value, expected_keys) do
    if Enum.sort(Map.keys(value)) != expected_keys,
      do: raise(ArgumentError, "unexpected_keys")

    :ok
  end

  defp assert_protocol_version!(@protocol_version), do: :ok
  defp assert_protocol_version!(_), do: raise(ArgumentError, "signature_protocol_version_invalid")

  defp assert_owner_kind!(value) when is_binary(value) do
    if MapSet.member?(@allowed_owner_kind_values, value),
      do: :ok,
      else: raise(ArgumentError, "owner_kind_invalid")
  end

  defp assert_owner_kind!(_), do: raise(ArgumentError, "owner_kind_invalid")

  defp assert_suite_fields!(@suite_id, @suite_rank), do: :ok
  defp assert_suite_fields!(_, _), do: raise(ArgumentError, "signature_suite_invalid")

  defp assert_signing_purpose!(value) do
    unless Regex.match?(~r/^[a-z][a-z0-9_]{0,63}$/, value),
      do: raise(ArgumentError, "signing_purpose_invalid")

    :ok
  end

  def assert_non_empty_string!(value, _error) when is_binary(value) and byte_size(value) > 0,
    do: :ok

  def assert_non_empty_string!(_, error), do: raise(ArgumentError, error)

  defp assert_literal!(value, expected, _error) when value == expected, do: :ok
  defp assert_literal!(_, _, error), do: raise(ArgumentError, error)

  defp mldsa_context!(signing_purpose) do
    context = @mldsa_context_prefix <> signing_purpose

    if byte_size(context) > 255,
      do: raise(ArgumentError, "mldsa_context_too_long"),
      else: context
  end

  defp constant_binary_equal?(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)
  end

  defp constant_binary_equal?(_, _), do: false
end
