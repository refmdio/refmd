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

    if valid_approval_inputs?(params, proof, commitments, approver_device, device_registration),
      do: {:ok, commitments, nil},
      else: {:error, :invalid_approval_commitments}
  end

  def approval_inputs_from_params(_, _, _, _), do: {:error, :invalid_approval_commitments}

  def delivery_artifact_matches?(
        purpose,
        %{"initial_ake" => initial_ake, "initial_key_delivery" => initial_key_delivery},
        commitment,
        approver_device,
        device_registration
      )
      when is_binary(purpose) and is_map(initial_ake) and is_map(initial_key_delivery) and
             is_map(commitment) and not is_nil(approver_device) do
    metadata = initial_key_delivery["metadata"]

    delivery_artifact_base_matches?(
      purpose,
      initial_ake,
      initial_key_delivery,
      commitment,
      metadata,
      approver_device,
      device_registration
    ) and delivery_artifact_purpose_matches?(purpose, initial_ake, commitment, metadata)
  rescue
    _ -> false
  end

  def delivery_artifact_matches?(_, _, _, _, _), do: false

  def kek_delivery_artifacts_match?(artifacts, commitments, approver_device, device_registration)
      when is_map(artifacts) and is_list(commitments) do
    map_size(artifacts) == length(commitments) and
      Enum.all?(commitments, fn commitment ->
        workspace_id = commitment["workspace_id"]

        is_binary(workspace_id) and
          delivery_artifact_matches?(
            "device_approval_kek_initial",
            artifacts[workspace_id],
            commitment,
            approver_device,
            device_registration
          )
      end)
  end

  def kek_delivery_artifacts_match?(_, _, _, _), do: false

  defp delivery_artifact_base_matches?(
         purpose,
         initial_ake,
         initial_key_delivery,
         commitment,
         metadata,
         approver_device,
         device_registration
       ) do
    is_map(metadata) and
      verify_initial_key_delivery_artifact?(
        purpose,
        initial_ake,
        initial_key_delivery,
        approver_device,
        device_registration
      ) and delivery_commitment_base_matches?(purpose, initial_key_delivery, commitment, metadata) and
      initial_key_delivery["protocol"] == "refmd.initial-key-delivery" and
      initial_key_delivery["purpose"] == purpose and
      initial_key_delivery["variant"] == purpose
  end

  defp delivery_commitment_base_matches?(purpose, initial_key_delivery, commitment, metadata) do
    commitment["purpose"] == purpose and
      commitment["variant"] == purpose and
      commitment["delivery_id"] == metadata["delivery_id"] and
      commitment["recipient_device_id"] == metadata["recipient_device_id"] and
      commitment["sender_device_id"] == metadata["sender_device_id"] and
      commitment["delivery_record_hash"] ==
        Hash.blake3_base64url(JCS.canonical_bytes!(initial_key_delivery)) and
      commitment["key_checkpoint_hash"] == metadata["key_checkpoint_hash"]
  end

  defp delivery_artifact_purpose_matches?("trust_transfer", initial_ake, commitment, metadata) do
    context = get_in(initial_ake, ["transcript", "context"])

    is_map(context) and commitment["ake_session_id"] == context["operation_id"] and
      commitment["document_rollback_pin_set_hash"] ==
        metadata["document_rollback_pin_set_hash"]
  end

  defp delivery_artifact_purpose_matches?(
         "device_approval_kek_initial",
         _initial_ake,
         commitment,
         metadata
       ) do
    commitment["workspace_id"] == metadata["workspace_id"] and
      commitment["key_version"] == metadata["key_version"]
  end

  defp delivery_artifact_purpose_matches?(_, _, _, _), do: true

  defp verify_initial_key_delivery_artifact?(
         purpose,
         initial_ake,
         initial_key_delivery,
         approver_device,
         device_registration
       ) do
    metadata = Map.fetch!(initial_key_delivery, "metadata")
    aead = Map.fetch!(initial_key_delivery, "aead")
    authority = Map.fetch!(initial_key_delivery, "authority")
    signature = Map.fetch!(initial_key_delivery, "signature")
    signing_body = Map.delete(initial_key_delivery, "signature")
    ake_transcript = Map.fetch!(initial_ake, "transcript")
    context = Map.fetch!(ake_transcript, "context")
    initiator_commitment = Map.fetch!(initial_ake, "initiator_commitment")
    transcript_hash = Hash.blake3_base64url(JCS.canonical_bytes!(ake_transcript))
    context_hash = Hash.blake3_base64url(JCS.canonical_bytes!(context))
    ciphertext_hash = Hash.blake3_base64url(Encoding.decode_base64url!(aead["ciphertext"]))
    initiator_commitment_hash = Hash.blake3_base64url(JCS.canonical_bytes!(initiator_commitment))

    commitment_transcript =
      Signature.build_initiator_ake_commitment_transcript!(
        metadata["sender_device_id"],
        initiator_commitment,
        Map.fetch!(initiator_commitment, "initiator"),
        Map.fetch!(initiator_commitment, "ake_inputs"),
        %{
          "operation_id" => context["operation_id"],
          "context_hash" => initiator_commitment["context_hash"],
          "directory_hash" => initiator_commitment["directory_hash"],
          "recipient_hash" => initiator_commitment["recipient_hash"],
          "server_challenge" => initiator_commitment["server_challenge"]
        }
      )

    signature_transcript =
      Signature.build_initial_key_delivery_transcript!(
        metadata["sender_device_id"],
        purpose,
        signing_body,
        %{
          "user_id" => approver_device.user_id,
          "device_id" => metadata["sender_device_id"],
          "signing_key_id" => signature["signing_key_id"]
        },
        %{
          "user_id" => approver_device.user_id,
          "device_id" => metadata["recipient_device_id"],
          "encryption_key_id" => metadata["recipient_encryption_key_id"]
        },
        %{
          "ake_transcript_hash" => transcript_hash,
          "initiator_commitment_hash" => initiator_commitment_hash,
          "purpose" => purpose,
          "operation_id" => context["operation_id"]
        },
        %{
          "delivery_id" => metadata["delivery_id"],
          "context_hash" => metadata["context_hash"],
          "payload_kind" => metadata["payload_kind"],
          "ciphertext_hash" => aead["ciphertext_hash"]
        },
        authority
      )

    Enum.all?([
      exact_keys?(initial_ake, [
        "protocol",
        "version",
        "ake_suite_id",
        "ake_suite_rank",
        "purpose",
        "transcript",
        "transcript_hash",
        "initiator_commitment",
        "initiator_commitment_signature",
        "initiator_confirmation",
        "responder_confirmation"
      ]),
      exact_keys?(initial_key_delivery, [
        "protocol",
        "version",
        "purpose",
        "variant",
        "initial_delivery_suite_id",
        "initial_delivery_suite_rank",
        "metadata",
        "aead",
        "authority",
        "signature"
      ]),
      exact_keys?(aead, ["suite_id", "suite_rank", "nonce", "ciphertext", "ciphertext_hash"]),
      initial_ake["protocol"] == "refmd.initial-hybrid-key-agreement",
      initial_ake["version"] == 1,
      initial_ake["ake_suite_id"] ==
        "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
      initial_ake["ake_suite_rank"] == 1000,
      initial_ake["purpose"] == purpose,
      initial_ake["transcript_hash"] == transcript_hash,
      initial_key_delivery["protocol"] == "refmd.initial-key-delivery",
      initial_key_delivery["version"] == 1,
      initial_key_delivery["initial_delivery_suite_id"] ==
        "refmd-v2-initial-delivery-xchacha20poly1305",
      initial_key_delivery["initial_delivery_suite_rank"] == 1000,
      initial_key_delivery["purpose"] == purpose,
      initial_key_delivery["variant"] == purpose,
      aead["suite_id"] == "refmd-v2-initial-delivery-xchacha20poly1305",
      aead["suite_rank"] == 1000,
      byte_size(Encoding.decode_base64url!(aead["nonce"])) == 24,
      metadata["ake_transcript_hash"] == transcript_hash,
      metadata["context_hash"] == context_hash,
      metadata["initiator_commitment_hash"] == initiator_commitment_hash,
      metadata["sender_device_id"] == approver_device.id,
      metadata["recipient_device_id"] == device_registration.id,
      metadata["signing_key_id"] == approver_device.signing_key_id,
      aead["ciphertext_hash"] == ciphertext_hash,
      signature["signing_key_id"] == approver_device.signing_key_id,
      get_in(ake_transcript, ["initiator", "device_id"]) == approver_device.id,
      get_in(ake_transcript, ["initiator", "signing_key_id"]) == approver_device.signing_key_id,
      get_in(ake_transcript, ["responder", "device_id"]) == device_registration.id,
      get_in(ake_transcript, ["context", "purpose"]) == purpose,
      get_in(ake_transcript, ["context", "operation_id"]) == context["operation_id"],
      context_targets_device?(purpose, context, device_registration.id),
      Signature.verify_hybrid_signature(
        "initiator_ake_commitment",
        commitment_transcript,
        initial_ake["initiator_commitment_signature"],
        approver_device.hybrid_signing_public_key_material
      ),
      Signature.verify_hybrid_signature(
        "initial_key_delivery",
        signature_transcript,
        signature,
        approver_device.hybrid_signing_public_key_material,
        %{delivery_signing_body: signing_body, authority: authority}
      )
    ])
  rescue
    _ -> false
  end

  defp context_targets_device?("trust_transfer", context, device_id),
    do: context["target_device_id"] == device_id

  defp context_targets_device?("device_approval_kek_initial", context, device_id),
    do: context["approved_device_id"] == device_id

  defp context_targets_device?(_, context, device_id),
    do: context["recipient_device_id"] == device_id

  defp valid_approval_inputs?(params, proof, commitments, approver_device, device_registration) do
    device_approval_proof?(proof) and device_approval_commitments?(commitments) and
      approval_participants_match?(params, approver_device, device_registration)
  end

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
