defmodule RefMD.Devices.Registrations.ApprovalDeliveryArtifacts do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}

  def approval_inputs_from_params(_params, true, _approver_device, _device_registration),
    do: {:ok, %{}, nil}

  def approval_inputs_from_params(params, false, approver_device, device_registration)
      when is_map(params) do
    proof = params["approval_proof"]
    details = if is_map(proof), do: proof["surface_details"], else: nil

    commitments = %{
      "umk_distribution_delivery_commitment" =>
        get_in(details || %{}, ["umk_distribution_delivery_commitment"]),
      "trust_transfer_delivery_commitment" =>
        get_in(details || %{}, ["trust_transfer_delivery_commitment"]),
      "device_approval_kek_initial_delivery_commitments" =>
        get_in(details || %{}, ["device_approval_kek_initial_delivery_commitments"])
    }

    offers = params["initial_ake_offers"]

    if valid_approval_inputs?(
         params,
         proof,
         commitments,
         offers,
         approver_device,
         device_registration
       ),
       do: {:ok, commitments, %{"initial_ake_offers" => offers}},
       else: {:error, :invalid_approval_commitments}
  end

  def approval_inputs_from_params(_, _, _, _), do: {:error, :invalid_approval_commitments}

  defp context_targets_device?("trust_transfer", context, device_id),
    do: context["target_device_id"] == device_id

  defp context_targets_device?("device_approval_kek_initial", context, device_id),
    do: context["approved_device_id"] == device_id

  defp context_targets_device?(_, context, device_id),
    do: context["recipient_device_id"] == device_id

  defp valid_approval_inputs?(
         params,
         proof,
         commitments,
         offers,
         approver_device,
         device_registration
       ) do
    device_approval_proof?(proof) and device_approval_commitments?(commitments) and
      approval_participants_match?(params, approver_device, device_registration) and
      initial_ake_offers_match?(offers, commitments, approver_device, device_registration)
  end

  defp initial_ake_offers_match?(offers, commitments, approver_device, device_registration)
       when is_map(offers) do
    kek_offers = offers["device_approval_kek_initial"]
    kek_commitments = commitments["device_approval_kek_initial_delivery_commitments"]

    exact_keys?(offers, [
      "device_approval_kek_initial",
      "trust_transfer",
      "umk_distribution"
    ]) and
      initial_ake_offer_matches?(
        "umk_distribution",
        offers["umk_distribution"],
        commitments["umk_distribution_delivery_commitment"],
        approver_device,
        device_registration
      ) and
      initial_ake_offer_matches?(
        "trust_transfer",
        offers["trust_transfer"],
        commitments["trust_transfer_delivery_commitment"],
        approver_device,
        device_registration
      ) and
      is_map(kek_offers) and is_list(kek_commitments) and
      map_size(kek_offers) == length(kek_commitments) and
      Enum.all?(kek_commitments, fn commitment ->
        workspace_id = commitment["workspace_id"]

        is_binary(workspace_id) and
          initial_ake_offer_matches?(
            "device_approval_kek_initial",
            kek_offers[workspace_id],
            commitment,
            approver_device,
            device_registration
          )
      end)
  end

  defp initial_ake_offers_match?(_, _, _, _), do: false

  defp initial_ake_offer_matches?(
         purpose,
         offer,
         commitment,
         approver_device,
         device_registration
       )
       when is_map(offer) and is_map(commitment) do
    transcript = offer["transcript"]
    initiator_commitment = offer["initiator_commitment"]
    pending_delivery = offer["pending_delivery"]
    metadata = pending_delivery["metadata"]
    aead = pending_delivery["aead"]
    context = transcript["context"]
    transcript_hash = Hash.blake3_base64url(JCS.canonical_bytes!(transcript))

    commitment_transcript =
      Signature.build_initiator_ake_commitment_transcript!(
        approver_device.id,
        initiator_commitment,
        initiator_commitment["initiator"],
        initiator_commitment["ake_inputs"],
        %{
          "operation_id" => context["operation_id"],
          "context_hash" => initiator_commitment["context_hash"],
          "directory_hash" => initiator_commitment["directory_hash"],
          "recipient_hash" => initiator_commitment["recipient_hash"],
          "server_challenge" => initiator_commitment["server_challenge"]
        }
      )

    Enum.all?([
      exact_keys?(offer, [
        "ake_suite_id",
        "ake_suite_rank",
        "initiator_commitment",
        "initiator_commitment_signature",
        "initiator_confirmation",
        "pending_delivery",
        "protocol",
        "purpose",
        "transcript",
        "transcript_hash",
        "version"
      ]),
      exact_keys?(pending_delivery, ["aead", "metadata"]),
      offer["protocol"] == "refmd.initial-hybrid-key-agreement",
      offer["version"] == 1,
      offer["ake_suite_id"] ==
        "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
      offer["ake_suite_rank"] == 1000,
      offer["purpose"] == purpose,
      offer["transcript_hash"] == transcript_hash,
      byte_size(Encoding.decode_base64url!(offer["initiator_confirmation"])) == 32,
      get_in(transcript, ["initiator", "device_id"]) == approver_device.id,
      get_in(transcript, ["initiator", "signing_key_id"]) == approver_device.signing_key_id,
      get_in(transcript, ["responder", "device_id"]) == device_registration.id,
      context_targets_device?(purpose, context, device_registration.id),
      metadata["sender_device_id"] == approver_device.id,
      metadata["recipient_device_id"] == device_registration.id,
      metadata["ake_transcript_hash"] == transcript_hash,
      aead["ciphertext_hash"] ==
        Hash.blake3_base64url(Encoding.decode_base64url!(aead["ciphertext"])),
      commitment["purpose"] == purpose,
      commitment["variant"] == purpose,
      commitment["delivery_id"] == metadata["delivery_id"],
      commitment["sender_device_id"] == approver_device.id,
      commitment["recipient_device_id"] == device_registration.id,
      commitment["delivery_record_hash"] ==
        Hash.blake3_base64url(JCS.canonical_bytes!(pending_delivery)),
      Signature.verify_hybrid_signature(
        "initiator_ake_commitment",
        commitment_transcript,
        offer["initiator_commitment_signature"],
        approver_device.hybrid_signing_public_key_material
      )
    ]) and offer_purpose_commitment_matches?(purpose, context, metadata, commitment)
  rescue
    _ -> false
  end

  defp initial_ake_offer_matches?(_, _, _, _, _), do: false

  def responses_match_offers?(responses, offers)
      when is_map(responses) and is_map(offers) do
    exact_keys?(responses, [
      "device_approval_kek_initial",
      "trust_transfer",
      "umk_distribution"
    ]) and
      response_matches_offer?(responses["umk_distribution"], offers["umk_distribution"]) and
      response_matches_offer?(responses["trust_transfer"], offers["trust_transfer"]) and
      response_map_matches_offers?(
        responses["device_approval_kek_initial"],
        offers["device_approval_kek_initial"]
      )
  end

  def responses_match_offers?(_, _), do: false

  defp response_map_matches_offers?(responses, offers)
       when is_map(responses) and is_map(offers) do
    Enum.sort(Map.keys(responses)) == Enum.sort(Map.keys(offers)) and
      Enum.all?(offers, fn {workspace_id, offer} ->
        response_matches_offer?(responses[workspace_id], offer)
      end)
  end

  defp response_map_matches_offers?(_, _), do: false

  defp response_matches_offer?(response, offer) when is_map(response) and is_map(offer) do
    transcript = offer["transcript"]

    exact_keys?(response, [
      "prekey_id",
      "protocol",
      "purpose",
      "responder_confirmation",
      "transcript_hash",
      "version"
    ]) and
      response["protocol"] == "refmd.initial-ake-responder-confirmation" and
      response["version"] == 1 and
      response["purpose"] == offer["purpose"] and
      response["transcript_hash"] == offer["transcript_hash"] and
      response["prekey_id"] == get_in(transcript, ["responder", "prekey_id"]) and
      byte_size(Encoding.decode_base64url!(response["responder_confirmation"])) == 32
  rescue
    _ -> false
  end

  defp response_matches_offer?(_, _), do: false

  defp offer_purpose_commitment_matches?("trust_transfer", context, metadata, commitment) do
    commitment["ake_session_id"] == context["operation_id"] and
      commitment["document_rollback_pin_set_hash"] ==
        metadata["document_rollback_pin_set_hash"]
  end

  defp offer_purpose_commitment_matches?(
         "device_approval_kek_initial",
         _context,
         metadata,
         commitment
       ) do
    commitment["workspace_id"] == metadata["workspace_id"] and
      commitment["key_version"] == metadata["key_version"]
  end

  defp offer_purpose_commitment_matches?(_, _, _, _), do: true

  defp approval_participants_match?(_params, approver_device, device_registration),
    do: is_map(approver_device) and is_map(device_registration)

  defp device_approval_proof?(proof) do
    is_map(proof) and proof["approval_signature_surface"] == "device_approval" and
      get_in(proof, ["surface_details", "kind"]) == "device_approval"
  end

  defp device_approval_commitments?(commitments) do
    is_map(commitments["umk_distribution_delivery_commitment"]) and
      is_map(commitments["trust_transfer_delivery_commitment"]) and
      is_list(commitments["device_approval_kek_initial_delivery_commitments"]) and
      sorted_commitments?(commitments["device_approval_kek_initial_delivery_commitments"])
  end

  defp sorted_commitments?(commitments) when is_list(commitments) do
    commitments == Enum.sort_by(commitments, &JCS.canonical_bytes!/1)
  rescue
    _ -> false
  end

  defp sorted_commitments?(_), do: false

  defp exact_keys?(map, expected) when is_map(map) do
    Map.keys(map) |> Enum.sort() == Enum.sort(expected)
  end

  defp exact_keys?(_, _), do: false
end
