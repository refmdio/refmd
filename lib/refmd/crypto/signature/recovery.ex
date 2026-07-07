defmodule RefMD.Crypto.Signature.Recovery do
  @moduledoc false

  @protocol_version 1

  import RefMD.Crypto.Signature.Core,
    only: [
      assert_map!: 2,
      assert_non_empty_string!: 2,
      assert_positive_integer!: 2,
      assert_transcript!: 4,
      transcript_base: 4
    ]

  alias RefMD.Crypto.{Encoding, Hash}
  alias RefMD.Crypto.HybridEncryptionMaterial
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.Signature
  alias RefMD.Crypto.SigningSurface

  def build_recovery_device_approval_transcript!(params) when is_map(params) do
    params = recovery_device_approval_params!(params)
    surface = SigningSurface.get_active!("recovery_device_approval", "none")

    encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(
        params.approved_device_hybrid_encryption_public_key_material
      )

    signing_material_hash =
      Hash.blake3_base64url(JCS.canonical_bytes!(params.approved_device_public_material))

    encryption_material_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(params.approved_device_hybrid_encryption_public_key_material)
      )

    target_client_nonce_hash =
      params.client_nonce
      |> Encoding.decode_base64url!()
      |> Hash.blake3_base64url()

    subject = %{
      "approval_signature_surface" => "recovery_device_approval",
      "approving_key_checkpoint_hash" => params.approving_key_checkpoint_hash,
      "approving_key_checkpoint_sequence" => params.approving_key_checkpoint_sequence,
      "approving_owner_id" => params.user_id,
      "approving_owner_kind" => "identity",
      "approving_signing_key_id" => params.approving_signing_key_id,
      "pending_registration_binding_hash" => params.pending_registration_binding_hash,
      "pending_registration_challenge_hash" => params.pending_registration_challenge_hash,
      "pending_registration_id" => params.pending_registration_id,
      "recovery_capability_hash" => params.recovery_capability_hash,
      "recovery_session_transcript_hash" => params.recovery_session_transcript_hash,
      "target_device_client_nonce_hash" => target_client_nonce_hash,
      "target_device_encryption_key_id" => encryption_key_id,
      "target_device_hybrid_encryption_public_key_material_hash" => encryption_material_hash,
      "target_device_hybrid_signing_public_key_material_hash" => signing_material_hash,
      "target_device_id" => params.approved_device_id,
      "target_device_signing_key_id" =>
        Signature.compute_signing_key_id!(params.approved_device_public_material),
      "target_key_checkpoint_hash" => params.target_key_checkpoint_hash,
      "target_key_checkpoint_sequence" => params.target_key_checkpoint_sequence
    }

    transcript =
      transcript_base("recovery_device_approval", surface, "identity", params.user_id)
      |> Map.merge(%{
        "approval_signature_surface" => subject["approval_signature_surface"],
        "approving_key_checkpoint_hash" => subject["approving_key_checkpoint_hash"],
        "approving_key_checkpoint_sequence" => subject["approving_key_checkpoint_sequence"],
        "approving_owner_id" => subject["approving_owner_id"],
        "approving_owner_kind" => subject["approving_owner_kind"],
        "approving_signing_key_id" => subject["approving_signing_key_id"],
        "pending_registration_binding_hash" => subject["pending_registration_binding_hash"],
        "pending_registration_challenge_hash" => subject["pending_registration_challenge_hash"],
        "pending_registration_id" => subject["pending_registration_id"],
        "recovery_capability_hash" => subject["recovery_capability_hash"],
        "recovery_session_transcript_hash" => subject["recovery_session_transcript_hash"],
        "target_device_client_nonce_hash" => subject["target_device_client_nonce_hash"],
        "target_device_encryption_key_id" => subject["target_device_encryption_key_id"],
        "target_device_hybrid_encryption_public_key_material_hash" =>
          subject["target_device_hybrid_encryption_public_key_material_hash"],
        "target_device_hybrid_signing_public_key_material_hash" =>
          subject["target_device_hybrid_signing_public_key_material_hash"],
        "target_device_id" => subject["target_device_id"],
        "target_device_signing_key_id" => subject["target_device_signing_key_id"],
        "target_key_checkpoint_hash" => subject["target_key_checkpoint_hash"],
        "target_key_checkpoint_sequence" => subject["target_key_checkpoint_sequence"]
      })

    assert_transcript!(transcript, "recovery_device_approval", "identity", params.user_id)
    transcript
  end

  def build_recovery_device_approval_transcript!(_),
    do: raise(ArgumentError, "recovery_device_approval_transcript_invalid")

  def build_recovery_session_transcript!(params) when is_map(params) do
    params = recovery_session_params!(params)
    surface = SigningSurface.get_active!("recovery_session", "none")

    transcript =
      transcript_base("recovery_session", surface, "identity", params.user_id)
      |> Map.merge(%{
        "subject_protocol" => "refmd.recovery-session",
        "subject_version" => @protocol_version,
        "owner_user_id" => params.user_id,
        "recipient_device_id" => params.recipient_device_id,
        "pending_registration_id" => params.pending_registration_id,
        "recovery_session_id" => params.recovery_session_id,
        "server_challenge_hash" => params.server_challenge_hash,
        "recovered_identity_signing_key_id" => params.recovered_identity_signing_key_id,
        "recovery_authorization_key_id" => params.recovery_authorization_key_id,
        "candidate_user_checkpoint_hash" => params.candidate_user_checkpoint_hash,
        "candidate_user_checkpoint_sequence" => params.candidate_user_checkpoint_sequence,
        "candidate_user_event_head_hash" => params.candidate_user_event_head_hash,
        "candidate_user_event_head_sequence" => params.candidate_user_event_head_sequence,
        "recovery_capability_hash" => params.recovery_capability_hash,
        "pending_registration_binding_hash" => params.pending_registration_binding_hash
      })

    assert_transcript!(transcript, "recovery_session", "identity", params.user_id)
    transcript
  end

  def build_recovery_session_transcript!(_),
    do: raise(ArgumentError, "recovery_session_transcript_invalid")

  def build_recovery_authorization_proof_transcript!(params) when is_map(params) do
    params = recovery_authorization_proof_params!(params)
    surface = SigningSurface.get_active!("recovery_authorization_proof", "none")

    transcript =
      transcript_base("recovery_authorization_proof", surface, "identity", params.user_id)
      |> Map.merge(%{
        "subject_protocol" => "refmd.recovery-authorization-proof",
        "subject_version" => @protocol_version,
        "recovery_authorization_key_id" => params.recovery_authorization_key_id,
        "recipient_device_id" => params.recipient_device_id,
        "pending_registration_binding_hash" => params.pending_registration_binding_hash,
        "server_challenge_hash" => params.server_challenge_hash
      })

    assert_transcript!(transcript, "recovery_authorization_proof", "identity", params.user_id)
    transcript
  end

  def build_recovery_authorization_proof_transcript!(_),
    do: raise(ArgumentError, "recovery_authorization_proof_transcript_invalid")

  def build_device_key_deletion_proof_transcript!(payload, actor)
      when is_map(payload) and is_map(actor) do
    variant = Map.get(payload, "deletion_proof_kind", "device_key_deletion_proof")
    surface = SigningSurface.get_active!("device_key_deletion_proof", variant)

    subject_hash = Hash.blake3_base64url(JCS.canonical_bytes!(payload))
    device_id = Map.fetch!(payload, "device_id")

    authority_boundary = %{
      "workspace_id" => Map.fetch!(payload, "workspace_id"),
      "rotation_kind" => Map.fetch!(payload, "rotation_kind"),
      "scope_kind" => Map.fetch!(payload, "scope_kind"),
      "scope_id" => Map.fetch!(payload, "scope_id"),
      "old_key_version" => Map.fetch!(payload, "old_key_version"),
      "rotation_completed_event_hash" => Map.fetch!(payload, "rotation_completed_event_hash"),
      "deleted_secret_ids_hash" => Map.fetch!(payload, "deleted_secret_ids_hash"),
      "deleted_storage_classes_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "storage_classes" => Enum.sort(Map.fetch!(payload, "deleted_storage_classes"))
          })
        )
    }

    transcript =
      transcript_base(
        "device_key_deletion_proof",
        surface,
        "device",
        device_id
      )
      |> Map.merge(%{
        "subject_hash" => subject_hash,
        "subject_protocol" => "refmd.device-key-deletion-proof",
        "subject_version" => @protocol_version,
        "actor" => actor,
        "authority_boundary" => authority_boundary
      })

    assert_transcript!(
      transcript,
      "device_key_deletion_proof",
      "device",
      device_id
    )

    transcript
  end

  def build_device_key_deletion_proof_transcript!(_, _),
    do: raise(ArgumentError, "device_key_deletion_proof_transcript_invalid")

  defp recovery_device_approval_params!(params) do
    invalid = "recovery_device_approval_transcript_invalid"

    assert_non_empty_string!(
      params[:user_id],
      invalid
    )

    assert_non_empty_string!(params[:approving_signing_key_id], invalid)
    assert_positive_integer!(params[:approving_key_checkpoint_sequence], invalid)
    assert_non_empty_string!(params[:approving_key_checkpoint_hash], invalid)
    assert_non_empty_string!(params[:pending_registration_id], invalid)
    assert_non_empty_string!(params[:pending_registration_challenge_hash], invalid)

    assert_non_empty_string!(
      params[:recovery_session_transcript_hash],
      invalid
    )

    assert_non_empty_string!(
      params[:recovery_capability_hash],
      invalid
    )

    assert_non_empty_string!(
      params[:pending_registration_binding_hash],
      invalid
    )

    assert_non_empty_string!(
      params[:approved_device_id],
      invalid
    )

    assert_map!(
      params[:approved_device_public_material],
      invalid
    )

    assert_map!(
      params[:approved_device_hybrid_encryption_public_key_material],
      invalid
    )

    assert_non_empty_string!(
      params[:client_nonce],
      invalid
    )

    assert_positive_integer!(params[:target_key_checkpoint_sequence], invalid)
    assert_non_empty_string!(params[:target_key_checkpoint_hash], invalid)

    params
  end

  defp recovery_session_params!(params) do
    assert_non_empty_string!(
      params[:user_id],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:recipient_device_id],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:pending_registration_id],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:recovery_session_id],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:server_challenge_hash],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:recovered_identity_signing_key_id],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:recovery_authorization_key_id],
      "recovery_session_transcript_invalid"
    )

    assert_positive_integer!(
      params[:candidate_user_checkpoint_sequence],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:candidate_user_checkpoint_hash],
      "recovery_session_transcript_invalid"
    )

    assert_positive_integer!(
      params[:candidate_user_event_head_sequence],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:candidate_user_event_head_hash],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:recovery_capability_hash],
      "recovery_session_transcript_invalid"
    )

    assert_non_empty_string!(
      params[:pending_registration_binding_hash],
      "recovery_session_transcript_invalid"
    )

    params
  end

  defp recovery_authorization_proof_params!(params) do
    invalid = "recovery_authorization_proof_transcript_invalid"

    assert_non_empty_string!(params[:user_id], invalid)
    assert_non_empty_string!(params[:recovery_authorization_key_id], invalid)
    assert_non_empty_string!(params[:recipient_device_id], invalid)
    assert_non_empty_string!(params[:pending_registration_binding_hash], invalid)
    assert_non_empty_string!(params[:server_challenge_hash], invalid)

    params
  end
end
