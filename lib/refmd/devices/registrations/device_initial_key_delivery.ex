defmodule RefMD.Devices.Registrations.DeviceInitialKeyDelivery do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature, Suite}

  @spec validate_bundle(binary(), binary(), map(), map(), map()) ::
          :ok | {:error, :invalid_initial_key_delivery}
  def validate_bundle(user_id, target_device_id, sender_device, target_device, params) do
    binding = %{
      user_id: user_id,
      target_device_id: target_device_id,
      sender_device_id: sender_device.id,
      sender_signing_key_id: sender_device.signing_key_id,
      sender_encryption_key_id: sender_device.encryption_key_id,
      sender_signing_public_key_material: sender_device.hybrid_signing_public_key_material,
      target_registration: target_device,
      target_encryption_key_id: target_device.encryption_key_id,
      approval_commitments: target_device.approval_delivery_commitments,
      params: params
    }

    with :ok <- validate_approval_commitments_present(binding),
         :ok <-
           validate_initial_ake_prekey(
             "umk_distribution",
             binding.params["initial_ake"],
             get_in(target_device.ake_responder_prekeys, ["umk_distribution", "payload"])
           ),
         :ok <-
           validate_initial_delivery_pair(
             "umk_distribution",
             binding.params["initial_ake"],
             binding.params["initial_key_delivery"],
             binding,
             %{},
             Map.get(binding.approval_commitments, "umk_distribution_delivery_commitment")
           ),
         :ok <-
           validate_device_state_delivery(binding.params["device_state_delivery"], binding),
         :ok <- validate_initial_kek_deliveries(binding.params["initial_kek_deliveries"], binding) do
      :ok
    else
      {:error, _} -> {:error, :invalid_initial_key_delivery}
    end
  end

  @spec prekey_consumptions_from_params(map()) ::
          {:ok, [map()]} | {:error, :invalid_initial_ake_prekey}
  def prekey_consumptions_from_params(params) do
    rows =
      [
        prekey_consumption(params["initial_ake"], params["initial_key_delivery"]),
        prekey_consumption(
          get_in(params, ["device_state_delivery", "initial_ake"]),
          get_in(params, ["device_state_delivery", "initial_key_delivery"])
        )
      ] ++
        Enum.map(params["initial_kek_deliveries"] || %{}, fn {_workspace_id, delivery} ->
          prekey_consumption(delivery["initial_ake"], delivery["initial_key_delivery"])
        end)

    if Enum.all?(rows, &is_map/1), do: {:ok, rows}, else: {:error, :invalid_initial_ake_prekey}
  rescue
    _ -> {:error, :invalid_initial_ake_prekey}
  end

  defp validate_approval_commitments_present(%{approval_commitments: commitments})
       when is_map(commitments) do
    if is_map(commitments["umk_distribution_delivery_commitment"]) and
         is_map(commitments["trust_transfer_delivery_commitment"]) and
         is_list(commitments["device_approval_kek_initial_delivery_commitments"]) and
         sorted_commitments?(commitments["device_approval_kek_initial_delivery_commitments"]) do
      :ok
    else
      {:error, :invalid_initial_key_delivery}
    end
  end

  defp validate_approval_commitments_present(_), do: {:error, :invalid_initial_key_delivery}

  defp sorted_commitments?(commitments) when is_list(commitments) do
    commitments == Enum.sort_by(commitments, &JCS.canonical_bytes!/1)
  rescue
    _ -> false
  end

  defp sorted_commitments?(_), do: false

  defp validate_initial_delivery_pair(
         purpose,
         initial_ake,
         initial_key_delivery,
         binding,
         expected,
         commitment
       ) do
    checks = [
      is_map(initial_ake) and is_map(initial_key_delivery),
      initial_delivery_protocol_matches?(purpose, initial_ake, initial_key_delivery),
      initial_ake_structure_valid?(purpose, initial_ake, binding, expected),
      initial_key_delivery_structure_valid?(purpose, initial_key_delivery),
      initial_delivery_suite_valid?(initial_key_delivery),
      initial_delivery_metadata_matches?(initial_ake, initial_key_delivery, binding, expected),
      delivery_commitment_matches?(purpose, initial_ake, initial_key_delivery, commitment)
    ]

    if Enum.all?(checks),
      do: verify_initial_delivery_signature(initial_ake, initial_key_delivery, binding),
      else: {:error, :invalid_initial_key_delivery}
  rescue
    _ -> {:error, :invalid_initial_key_delivery}
  end

  defp initial_delivery_protocol_matches?(purpose, initial_ake, initial_key_delivery) do
    [
      {initial_ake["protocol"], "refmd.initial-hybrid-key-agreement"},
      {initial_ake["purpose"], purpose},
      {initial_key_delivery["protocol"], "refmd.initial-key-delivery"},
      {initial_key_delivery["purpose"], purpose},
      {initial_key_delivery["variant"], purpose}
    ]
    |> Enum.all?(fn {actual, expected} -> actual == expected end)
  end

  defp initial_delivery_metadata_matches?(initial_ake, initial_key_delivery, binding, expected) do
    metadata = initial_key_delivery["metadata"]

    initial_delivery_metadata_values_match?(initial_ake, metadata, binding) and
      initial_delivery_metadata_hashes_match?(initial_ake, metadata) and
      expected_metadata_matches?(metadata, expected)
  end

  defp initial_delivery_metadata_values_match?(initial_ake, metadata, binding) do
    [
      {metadata["sender_device_id"], binding.sender_device_id},
      {metadata["recipient_device_id"], binding.target_device_id},
      {metadata["recipient_encryption_key_id"], binding.target_encryption_key_id},
      {metadata["ake_transcript_hash"], initial_ake["transcript_hash"]},
      {metadata["signing_key_id"], binding.sender_signing_key_id}
    ]
    |> Enum.all?(fn {actual, expected} -> actual == expected end)
  end

  defp initial_delivery_metadata_hashes_match?(initial_ake, metadata) do
    initiator_commitment_hash =
      Hash.blake3_base64url(JCS.canonical_bytes!(initial_ake["initiator_commitment"]))

    transcript_hash = Hash.blake3_base64url(JCS.canonical_bytes!(initial_ake["transcript"]))

    metadata["initiator_commitment_hash"] == initiator_commitment_hash and
      transcript_hash == initial_ake["transcript_hash"]
  end

  defp validate_device_state_delivery(
         %{"initial_ake" => initial_ake, "initial_key_delivery" => initial_key_delivery},
         binding
       ) do
    with :ok <-
           validate_initial_ake_prekey(
             "trust_transfer",
             initial_ake,
             get_in(binding.target_registration.ake_responder_prekeys, [
               "trust_transfer",
               "payload"
             ])
           ) do
      validate_initial_delivery_pair(
        "trust_transfer",
        initial_ake,
        initial_key_delivery,
        binding,
        %{
          "payload_kind" => "trust_state_bundle",
          "key_kind" => "trust_state_bundle"
        },
        Map.get(binding.approval_commitments, "trust_transfer_delivery_commitment")
      )
    end
  end

  defp validate_device_state_delivery(_, _), do: {:error, :invalid_initial_key_delivery}

  defp initial_delivery_suite_valid?(%{
         "initial_delivery_suite_id" => suite_id,
         "initial_delivery_suite_rank" => suite_rank,
         "metadata" => %{"suite_id" => suite_id, "suite_rank" => suite_rank},
         "aead" => %{"suite_id" => suite_id, "suite_rank" => suite_rank}
       }) do
    suite_id == Suite.initial_delivery_suite_id() and suite_rank == Suite.current_suite_rank()
  end

  defp initial_delivery_suite_valid?(_), do: false

  defp initial_key_delivery_structure_valid?(purpose, delivery) when is_map(delivery) do
    metadata = delivery["metadata"]
    aead = delivery["aead"]
    authority = delivery["authority"]

    exact_keys?(delivery, [
      "aead",
      "authority",
      "initial_delivery_suite_id",
      "initial_delivery_suite_rank",
      "metadata",
      "protocol",
      "purpose",
      "signature",
      "variant",
      "version"
    ]) and
      exact_keys?(aead, ["ciphertext", "ciphertext_hash", "nonce", "suite_id", "suite_rank"]) and
      aead_ciphertext_hash_valid?(aead) and
      exact_keys?(authority, ["sender_authority_kind"]) and
      authority["sender_authority_kind"] == "device" and
      initial_key_delivery_metadata_keys_valid?(purpose, metadata)
  end

  defp initial_key_delivery_structure_valid?(_, _), do: false

  defp aead_ciphertext_hash_valid?(%{"ciphertext" => ciphertext, "ciphertext_hash" => hash})
       when is_binary(ciphertext) and is_binary(hash) do
    Hash.blake3_base64url(Encoding.decode_base64url!(ciphertext)) == hash
  rescue
    ArgumentError -> false
  end

  defp aead_ciphertext_hash_valid?(_), do: false

  defp initial_key_delivery_metadata_keys_valid?("umk_distribution", metadata)
       when is_map(metadata),
       do: exact_keys?(metadata, initial_delivery_common_metadata_keys())

  defp initial_key_delivery_metadata_keys_valid?("trust_transfer", metadata)
       when is_map(metadata),
       do:
         exact_keys?(
           metadata,
           initial_delivery_common_metadata_keys() ++ ["document_rollback_pin_set_hash"]
         )

  defp initial_key_delivery_metadata_keys_valid?("device_approval_kek_initial", metadata)
       when is_map(metadata),
       do: exact_keys?(metadata, initial_delivery_common_metadata_keys() ++ ["workspace_id"])

  defp initial_key_delivery_metadata_keys_valid?(_, _), do: false

  defp initial_delivery_common_metadata_keys do
    [
      "ake_transcript_hash",
      "context_hash",
      "delivery_id",
      "initiator_commitment_hash",
      "key_checkpoint_hash",
      "key_confirmation_hash",
      "key_kind",
      "key_version",
      "payload_kind",
      "recipient_challenge_hash",
      "recipient_device_id",
      "recipient_encryption_key_id",
      "resource_hash",
      "sender_device_id",
      "signing_key_id",
      "suite_id",
      "suite_rank"
    ]
  end

  defp validate_initial_kek_deliveries(deliveries, binding) when is_map(deliveries) do
    commitments = binding.approval_commitments["device_approval_kek_initial_delivery_commitments"]

    with :ok <- validate_kek_delivery_count(deliveries, commitments),
         {:ok, seen} <- validate_kek_delivery_records(deliveries, commitments, binding) do
      if MapSet.size(seen) == length(commitments),
        do: :ok,
        else: {:error, :invalid_initial_key_delivery}
    end
  end

  defp validate_initial_kek_deliveries(_, _), do: {:error, :invalid_initial_key_delivery}

  defp validate_kek_delivery_count(deliveries, commitments)
       when is_map(deliveries) and is_list(commitments) do
    if length(commitments) == map_size(deliveries),
      do: :ok,
      else: {:error, :invalid_initial_key_delivery}
  end

  defp validate_kek_delivery_count(_, _), do: {:error, :invalid_initial_key_delivery}

  defp validate_kek_delivery_records(deliveries, commitments, binding) do
    deliveries
    |> Enum.reduce_while(MapSet.new(), fn delivery, seen ->
      case validate_one_kek_delivery(delivery, seen, commitments, binding) do
        {:ok, key} -> {:cont, MapSet.put(seen, key)}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      %MapSet{} = seen -> {:ok, seen}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_initial_key_delivery}
    end
  end

  defp validate_one_kek_delivery(
         {workspace_id,
          %{"initial_ake" => initial_ake, "initial_key_delivery" => initial_key_delivery}},
         seen,
         commitments,
         binding
       ) do
    metadata = initial_key_delivery["metadata"]
    commitment_key = {workspace_id, metadata["key_version"], metadata["delivery_id"]}

    with false <- MapSet.member?(seen, commitment_key),
         :ok <- validate_kek_delivery_prekey(workspace_id, initial_ake, binding),
         :ok <-
           validate_initial_delivery_pair(
             "device_approval_kek_initial",
             initial_ake,
             initial_key_delivery,
             binding,
             %{"workspace_id" => workspace_id, "key_version" => metadata["key_version"]},
             find_kek_delivery_commitment(
               commitments,
               workspace_id,
               metadata["key_version"],
               metadata["delivery_id"]
             )
           ) do
      {:ok, commitment_key}
    else
      _ -> {:error, :invalid_initial_key_delivery}
    end
  end

  defp validate_one_kek_delivery(_, _, _, _), do: {:error, :invalid_initial_key_delivery}

  defp validate_kek_delivery_prekey(workspace_id, initial_ake, binding) do
    stored_prekey =
      get_in(binding.target_registration.ake_responder_prekeys, [
        "device_approval_kek_initial:" <> workspace_id,
        "payload"
      ])

    validate_initial_ake_prekey("device_approval_kek_initial", initial_ake, stored_prekey)
  end

  defp validate_initial_ake_prekey(purpose, initial_ake, stored_prekey)
       when is_binary(purpose) and is_map(initial_ake) and is_map(stored_prekey) do
    transcript = initial_ake["transcript"]
    responder = transcript["responder"]
    context = transcript["context"]
    stored_prekey_hash = Hash.blake3_base64url(JCS.canonical_bytes!(stored_prekey))

    if Enum.all?([
         initial_ake["purpose"] == purpose,
         stored_prekey["purpose"] == purpose,
         responder["prekey_id"] == stored_prekey["prekey_id"],
         responder["prekey_hash"] == stored_prekey_hash,
         responder["signing_key_id"] == stored_prekey["responder_signing_key_id"],
         responder["x25519_ephemeral_public"] == stored_prekey["x25519_ephemeral_public"],
         responder["mlkem768_ephemeral_public_hash"] ==
           stored_prekey["mlkem768_ephemeral_public_hash"],
         context["operation_id"] == stored_prekey["operation_id"],
         context["challenge"] == stored_prekey["server_challenge"]
       ]),
       do: :ok,
       else: {:error, :invalid_initial_key_delivery}
  rescue
    _ -> {:error, :invalid_initial_key_delivery}
  end

  defp validate_initial_ake_prekey(_, _, _), do: {:error, :invalid_initial_key_delivery}

  defp initial_ake_structure_valid?(purpose, initial_ake, binding, expected) do
    transcript = initial_ake["transcript"]
    context = transcript["context"]
    responder = transcript["responder"]
    commitment = initial_ake["initiator_commitment"]
    signature = initial_ake["initiator_commitment_signature"]

    expected_components = [
      "x25519-ephemeral",
      "mlkem768-ephemeral",
      "hkdf-sha256",
      "initiator-ake-commitment",
      "responder-prekey-signature"
    ]

    binding_payload = %{
      "operation_id" => context["operation_id"],
      "context_hash" => commitment["context_hash"],
      "directory_hash" => commitment["directory_hash"],
      "recipient_hash" => commitment["recipient_hash"],
      "server_challenge" => context["challenge"]
    }

    transcript_payload =
      Signature.build_initiator_ake_commitment_transcript!(
        binding.sender_device_id,
        commitment,
        commitment["initiator"],
        commitment["ake_inputs"],
        binding_payload
      )

    Enum.all?([
      exact_keys?(initial_ake, [
        "ake_suite_id",
        "ake_suite_rank",
        "initiator_commitment",
        "initiator_commitment_signature",
        "initiator_confirmation",
        "protocol",
        "purpose",
        "responder_confirmation",
        "transcript",
        "transcript_hash",
        "version"
      ]),
      exact_keys?(transcript, [
        "ake_suite_id",
        "ake_suite_rank",
        "context",
        "directory",
        "initiator",
        "protocol",
        "purpose",
        "required_components",
        "responder",
        "version"
      ]),
      initial_ake["protocol"] == "refmd.initial-hybrid-key-agreement",
      initial_ake["version"] == 1,
      initial_ake["ake_suite_id"] ==
        "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
      initial_ake["ake_suite_rank"] == 1000,
      initial_ake["purpose"] == purpose,
      base64url_byte_size?(initial_ake["initiator_confirmation"], 32),
      base64url_byte_size?(initial_ake["responder_confirmation"], 32),
      transcript["protocol"] == "refmd.initial-hybrid-key-agreement",
      transcript["version"] == 1,
      transcript["ake_suite_id"] ==
        "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
      transcript["ake_suite_rank"] == 1000,
      transcript["purpose"] == purpose,
      transcript["required_components"] == expected_components,
      commitment["protocol"] == "refmd.initiator-ake-commitment",
      commitment["version"] == 1,
      commitment["ake_suite_id"] ==
        "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
      commitment["ake_suite_rank"] == 1000,
      commitment["initial_delivery_suite_id"] ==
        "refmd-v2-initial-delivery-xchacha20poly1305",
      commitment["initial_delivery_suite_rank"] == 1000,
      commitment["purpose"] == purpose,
      commitment["operation_id"] == context["operation_id"],
      Hash.blake3_base64url(JCS.canonical_bytes!(commitment)) ==
        get_in(transcript, ["initiator", "initiator_commitment_hash"]),
      get_in(commitment, ["ake_inputs", "x25519_ephemeral_public"]) ==
        get_in(transcript, ["initiator", "x25519_ephemeral_public"]),
      get_in(commitment, ["ake_inputs", "mlkem768_enc"]) ==
        get_in(transcript, ["initiator", "mlkem768_enc"]),
      get_in(commitment, ["ake_inputs", "responder_prekey_hash"]) == responder["prekey_hash"],
      pending_registration_binding_valid?(commitment["initiator"], binding),
      commitment["context_hash"] == Hash.blake3_base64url(JCS.canonical_bytes!(context)),
      initial_ake_context_valid?(purpose, context, binding, expected),
      initial_ake_directory_valid?(purpose, transcript["directory"]),
      commitment["directory_hash"] ==
        Hash.blake3_base64url(JCS.canonical_bytes!(transcript["directory"])),
      commitment["recipient_hash"] ==
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "user_id" => binding.user_id,
            "device_id" => binding.target_device_id,
            "encryption_key_id" => binding.target_encryption_key_id,
            "prekey_hash" => responder["prekey_hash"]
          })
        ),
      commitment["server_challenge"] == context["challenge"],
      Signature.verify_hybrid_signature(
        "initiator_ake_commitment",
        transcript_payload,
        signature,
        binding.sender_signing_public_key_material
      )
    ])
  rescue
    _ -> false
  end

  defp initial_ake_context_valid?("umk_distribution", context, binding, _expected)
       when is_map(context),
       do:
         context_exact?(context, umk_distribution_context_keys()) and
           umk_distribution_context_binding_valid?(context, binding)

  defp initial_ake_context_valid?("device_approval_kek_initial", context, binding, expected)
       when is_map(context) and is_map(expected),
       do:
         context_exact?(context, device_approval_kek_context_keys()) and
           device_approval_kek_context_binding_valid?(context, binding, expected)

  defp initial_ake_context_valid?("trust_transfer", context, binding, _expected)
       when is_map(context),
       do:
         context_exact?(context, trust_transfer_context_keys()) and
           trust_transfer_context_binding_valid?(context, binding)

  defp initial_ake_context_valid?(_, _context, _binding, _expected), do: false

  defp context_exact?(context, keys), do: exact_keys?(context, keys)

  defp umk_distribution_context_binding_valid?(context, binding) do
    Enum.all?([
      context["purpose"] == "umk_distribution",
      context["owner_user_id"] == binding.user_id,
      context["recipient_device_id"] == binding.target_device_id,
      context["target_key_kind"] == "umk",
      context["target_key_version"] == 1,
      context["distribution_id"] == context["operation_id"]
    ])
  end

  defp device_approval_kek_context_binding_valid?(context, binding, expected) do
    Enum.all?([
      context["purpose"] == "device_approval_kek_initial",
      context["owner_user_id"] == binding.user_id,
      context["approved_device_id"] == binding.target_device_id,
      context["registration_id"] == context["operation_id"],
      context["registration_id"] == binding.target_device_id,
      context["target_key_kind"] == "kek",
      context["target_key_version"] == expected["key_version"],
      context["workspace_id"] == expected["workspace_id"]
    ])
  end

  defp trust_transfer_context_binding_valid?(context, binding) do
    Enum.all?([
      context["purpose"] == "trust_transfer",
      context["owner_user_id"] == binding.user_id,
      context["source_device_id"] == binding.sender_device_id,
      context["target_device_id"] == binding.target_device_id,
      context["target_payload_kind"] == "trust_state_bundle",
      context["trust_transfer_id"] == context["operation_id"],
      context["transfer_scope_hash"] == trust_transfer_scope_hash(binding)
    ])
  end

  defp trust_transfer_scope_hash(binding) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "user_id" => binding.user_id,
        "source_device_id" => binding.sender_device_id,
        "target_device_id" => binding.target_device_id
      })
    )
  end

  defp umk_distribution_context_keys do
    [
      "challenge",
      "distribution_id",
      "operation_id",
      "owner_user_id",
      "purpose",
      "recipient_device_id",
      "target_key_kind",
      "target_key_version"
    ]
  end

  defp device_approval_kek_context_keys do
    [
      "approved_device_id",
      "challenge",
      "operation_id",
      "owner_user_id",
      "purpose",
      "registration_id",
      "target_key_kind",
      "target_key_version",
      "workspace_id"
    ]
  end

  defp trust_transfer_context_keys do
    [
      "challenge",
      "operation_id",
      "owner_user_id",
      "purpose",
      "source_device_id",
      "target_device_id",
      "target_payload_kind",
      "transfer_scope_hash",
      "trust_transfer_id"
    ]
  end

  defp pending_registration_binding_valid?(initiator, binding) when is_map(initiator) do
    initiator["signer_kind"] == "active_device" and
      initiator["user_id"] == binding.user_id and
      initiator["device_id"] == binding.sender_device_id and
      initiator["signing_key_id"] == binding.sender_signing_key_id and
      initiator["encryption_key_id"] == binding.sender_encryption_key_id and
      is_binary(initiator["pending_registration_binding_hash"]) and
      initiator["pending_registration_binding_hash"] ==
        pending_registration_binding_hash!(binding)
  rescue
    _ -> false
  end

  defp pending_registration_binding_valid?(_, _), do: false

  defp pending_registration_binding_hash!(binding) do
    registration = binding.target_registration
    user_checkpoint = get_in(registration.approval_key_directory, ["user_checkpoint"])
    checkpoint_payload = user_checkpoint["payload"]

    payload = %{
      "protocol" => "refmd.pending-registration-binding",
      "version" => 1,
      "user_id" => binding.user_id,
      "pending_registration_id" => registration.id,
      "pending_registration_challenge_hash" => registration.pending_registration_challenge_hash,
      "target_device_id" => registration.id,
      "target_device_signing_key_id" => registration.signing_key_id,
      "target_device_hybrid_signing_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(registration.hybrid_signing_public_key_material)
        ),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(registration.hybrid_encryption_public_key_material)
        ),
      "target_device_encryption_key_id" => registration.encryption_key_id,
      "target_device_client_nonce_hash" => Hash.blake3_base64url(registration.client_nonce),
      "target_key_checkpoint_sequence" => checkpoint_payload["sequence"],
      "target_key_checkpoint_hash" => key_directory_checkpoint_hash(checkpoint_payload)
    }

    Hash.blake3_base64url(JCS.canonical_bytes!(payload))
  end

  defp key_directory_checkpoint_hash(payload),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(payload))

  defp initial_ake_directory_valid?("umk_distribution", directory) when is_map(directory) do
    exact_directory_keys?(directory, [
      "allowed_suite_ids_hash",
      "min_suite_rank",
      "suite_policy_version",
      "user_checkpoint_hash",
      "user_event_head_hash"
    ])
  end

  defp initial_ake_directory_valid?("device_approval_kek_initial", directory)
       when is_map(directory) do
    exact_directory_keys?(directory, [
      "allowed_suite_ids_hash",
      "event_head_hash",
      "min_suite_rank",
      "suite_policy_version",
      "user_checkpoint_hash",
      "workspace_checkpoint_hash"
    ])
  end

  defp initial_ake_directory_valid?("trust_transfer", directory) when is_map(directory) do
    exact_directory_keys?(directory, [
      "allowed_suite_ids_hash",
      "min_suite_rank",
      "suite_policy_version",
      "user_checkpoint_hash",
      "user_event_head_hash",
      "workspace_pins_hash"
    ])
  end

  defp initial_ake_directory_valid?(_, _), do: false

  defp exact_keys?(value, keys) when is_map(value),
    do: Map.keys(value) |> Enum.sort() == Enum.sort(keys)

  defp exact_keys?(_, _), do: false

  defp base64url_byte_size?(value, size) when is_binary(value) do
    Encoding.decode_base64url!(value, size)
    true
  rescue
    ArgumentError -> false
  end

  defp base64url_byte_size?(_, _), do: false

  defp exact_directory_keys?(directory, keys) do
    hash_keys = keys -- ["suite_policy_version", "min_suite_rank"]
    policy = Suite.current_suite_policy()

    Map.keys(directory) |> Enum.sort() == Enum.sort(keys) and
      Enum.all?(hash_keys, &hash_value?(directory[&1])) and
      directory["suite_policy_version"] == policy["suite_policy_version"] and
      directory["min_suite_rank"] == policy["min_suite_rank"] and
      directory["allowed_suite_ids_hash"] == policy["allowed_suite_ids_hash"]
  end

  defp hash_value?(value), do: is_binary(value) and value =~ ~r/^[A-Za-z0-9_-]{43}$/

  defp prekey_consumption(initial_ake, initial_key_delivery)
       when is_map(initial_ake) and is_map(initial_key_delivery) do
    transcript = initial_ake["transcript"]
    responder = transcript["responder"]
    context = transcript["context"]
    metadata = initial_key_delivery["metadata"]

    %{
      prekey_id: responder["prekey_id"],
      operation_id: context["operation_id"],
      purpose: initial_ake["purpose"],
      delivery_id: metadata["delivery_id"],
      delivery_hash: Hash.blake3_base64url(JCS.canonical_bytes!(initial_key_delivery))
    }
  end

  defp prekey_consumption(_, _), do: nil

  defp expected_metadata_matches?(metadata, expected)
       when is_map(metadata) and is_map(expected),
       do: Enum.all?(expected, fn {key, value} -> metadata[key] == value end)

  defp expected_metadata_matches?(_, _), do: false

  defp delivery_commitment_matches?(purpose, initial_ake, initial_key_delivery, commitment)
       when is_map(commitment) do
    metadata = initial_key_delivery["metadata"]

    delivery_commitment_base_matches?(purpose, initial_key_delivery, commitment, metadata) and
      delivery_commitment_purpose_matches?(purpose, initial_ake, commitment, metadata)
  rescue
    _ -> false
  end

  defp delivery_commitment_matches?(_, _, _, _), do: false

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

  defp delivery_commitment_purpose_matches?("trust_transfer", initial_ake, commitment, metadata) do
    context = get_in(initial_ake, ["transcript", "context"])

    is_map(context) and commitment["ake_session_id"] == context["operation_id"] and
      commitment["document_rollback_pin_set_hash"] == metadata["document_rollback_pin_set_hash"]
  end

  defp delivery_commitment_purpose_matches?(
         "device_approval_kek_initial",
         _initial_ake,
         commitment,
         metadata
       ) do
    commitment["workspace_id"] == metadata["workspace_id"] and
      commitment["key_version"] == metadata["key_version"]
  end

  defp delivery_commitment_purpose_matches?(_, _, _, _), do: true

  defp find_kek_delivery_commitment(commitments, workspace_id, key_version, delivery_id)
       when is_list(commitments) do
    Enum.find(commitments, fn commitment ->
      is_map(commitment) and commitment["workspace_id"] == workspace_id and
        commitment["key_version"] == key_version and commitment["delivery_id"] == delivery_id
    end)
  end

  defp find_kek_delivery_commitment(_, _, _, _), do: nil

  defp verify_initial_delivery_signature(initial_ake, initial_key_delivery, binding) do
    signing_body = Map.delete(initial_key_delivery, "signature")
    metadata = initial_key_delivery["metadata"]
    aead = initial_key_delivery["aead"]
    transcript = initial_ake["transcript"]
    context = transcript["context"]

    signature_transcript =
      Signature.build_initial_key_delivery_transcript!(
        binding.sender_device_id,
        initial_key_delivery["variant"],
        signing_body,
        %{
          "user_id" => binding.user_id,
          "device_id" => binding.sender_device_id,
          "signing_key_id" => initial_key_delivery["signature"]["signing_key_id"]
        },
        %{
          "user_id" => binding.user_id,
          "device_id" => binding.target_device_id,
          "encryption_key_id" => metadata["recipient_encryption_key_id"]
        },
        %{
          "ake_transcript_hash" => initial_ake["transcript_hash"],
          "initiator_commitment_hash" => metadata["initiator_commitment_hash"],
          "purpose" => initial_ake["purpose"],
          "operation_id" => context["operation_id"]
        },
        %{
          "delivery_id" => metadata["delivery_id"],
          "context_hash" => metadata["context_hash"],
          "payload_kind" => metadata["payload_kind"],
          "ciphertext_hash" => aead["ciphertext_hash"]
        },
        initial_key_delivery["authority"]
      )

    if Signature.verify_hybrid_signature(
         "initial_key_delivery",
         signature_transcript,
         initial_key_delivery["signature"],
         binding.sender_signing_public_key_material,
         %{
           delivery_signing_body: signing_body,
           authority: initial_key_delivery["authority"]
         }
       ) do
      :ok
    else
      {:error, :invalid_initial_key_delivery}
    end
  rescue
    _ -> {:error, :invalid_initial_key_delivery}
  end
end
