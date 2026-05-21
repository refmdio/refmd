defmodule RefMD.Crypto.Signature.ApprovalProof do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}

  @protocol "refmd.device-approval-proof"
  @version 1

  @spec build!(binary(), map(), map()) :: map()
  def build!(approval_signature_surface, transcript, surface_details) do
    build!(approval_signature_surface, transcript, surface_details, %{})
  end

  @spec build!(binary(), map(), map(), map()) :: map()
  def build!(approval_signature_surface, transcript, surface_details, proof_context)
      when is_binary(approval_signature_surface) and is_map(transcript) and
             is_map(surface_details) and is_map(proof_context) do
    %{
      "protocol" => @protocol,
      "version" => @version,
      "approval_signature_surface" => approval_signature_surface,
      "approval_transcript_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(transcript)),
      "approval_transcript_owner" => Map.fetch!(transcript, "transcript_owner"),
      "approval_surface_id" => Map.fetch!(transcript, "surface_id"),
      "approval_surface_variant" => Map.fetch!(transcript, "surface_variant"),
      "approving_owner_kind" => Map.fetch!(transcript, "owner_kind"),
      "approving_owner_id" => Map.fetch!(transcript, "owner_id"),
      "approving_signing_key_id" =>
        proof_field!(proof_context, transcript, "approving_signing_key_id"),
      "approving_key_checkpoint_sequence" =>
        proof_field!(proof_context, transcript, "approving_key_checkpoint_sequence"),
      "approving_key_checkpoint_hash" =>
        proof_field!(proof_context, transcript, "approving_key_checkpoint_hash"),
      "target_device_id" => proof_field!(proof_context, transcript, "target_device_id"),
      "target_device_signing_key_id" =>
        proof_field!(proof_context, transcript, "target_device_signing_key_id"),
      "target_device_hybrid_signing_public_key_material_hash" =>
        proof_field!(
          proof_context,
          transcript,
          "target_device_hybrid_signing_public_key_material_hash"
        ),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        proof_field!(
          proof_context,
          transcript,
          "target_device_hybrid_encryption_public_key_material_hash"
        ),
      "target_device_encryption_key_id" =>
        proof_field!(proof_context, transcript, "target_device_encryption_key_id"),
      "target_device_client_nonce_hash" =>
        proof_field!(proof_context, transcript, "target_device_client_nonce_hash"),
      "target_key_checkpoint_sequence" =>
        proof_field!(proof_context, transcript, "target_key_checkpoint_sequence"),
      "target_key_checkpoint_hash" =>
        proof_field!(proof_context, transcript, "target_key_checkpoint_hash"),
      "surface_details" => surface_details
    }
  end

  def build!(_, _, _, _), do: raise(ArgumentError, "approval_proof_invalid")

  defp proof_field!(proof_context, transcript, field) do
    cond do
      Map.has_key?(proof_context, field) -> Map.fetch!(proof_context, field)
      Map.has_key?(transcript, field) -> Map.fetch!(transcript, field)
      true -> raise KeyError, key: field, term: transcript
    end
  end
end
