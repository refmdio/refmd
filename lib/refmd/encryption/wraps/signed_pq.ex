defmodule RefMD.Encryption.Wraps.SignedPQ do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature, Suite}

  @wrap_protocol "refmd.signed-pq-hybrid-wrap"
  @wrap_suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @signature_protocol "refmd.hybrid-signature"
  @signature_suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"
  @kem_id 0x647A
  @kdf_id 0x0001
  @aead_id 0x0003
  @hpke_enc_bytes 1120
  @ed25519_signature_bytes 64
  @mldsa65_signature_bytes 3309

  @binary_fields [
    "wrap_event_hash",
    "wrap_event_body_hash",
    "operation_checkpoint_hash",
    "operation_checkpoint_covered_head_hash",
    "wrap_body_hash",
    "recipient_key_id",
    "sender_signing_key_id",
    "transcript_hash",
    "ed25519_signature",
    "mldsa65_signature"
  ]
  @binary_field_atoms %{
    "wrap_event_hash" => :wrap_event_hash,
    "wrap_event_body_hash" => :wrap_event_body_hash,
    "operation_checkpoint_hash" => :operation_checkpoint_hash,
    "operation_checkpoint_covered_head_hash" => :operation_checkpoint_covered_head_hash,
    "wrap_body_hash" => :wrap_body_hash,
    "recipient_key_id" => :recipient_key_id,
    "sender_signing_key_id" => :sender_signing_key_id,
    "transcript_hash" => :transcript_hash,
    "ed25519_signature" => :ed25519_signature,
    "mldsa65_signature" => :mldsa65_signature
  }

  @string_fields [
    :wrap_protocol,
    :suite_id,
    :purpose
  ]

  @integer_fields [
    :wrap_version,
    :suite_rank,
    :kem_id,
    :kdf_id,
    :aead_id,
    :wrap_event_sequence,
    :operation_checkpoint_sequence,
    :operation_checkpoint_covered_head_sequence
  ]

  @map_fields [:resource, :sender, :recipient, :event_scope]
  @container_field_names [
    "device_id",
    "is_active",
    "key_version",
    "sender_approval_delivery_commitments",
    "sender_client_nonce",
    "sender_device_id",
    "sender_hybrid_encryption_public_key_material",
    "sender_hybrid_signing_public_key_material",
    "sender_identity_hybrid_encryption_public_key_material",
    "sender_approval_signature",
    "sender_identity_hybrid_signing_public_key_material",
    "sender_approval_proof",
    "sender_approval_signature_surface",
    "sender_user_id",
    "target_device_id",
    "target_user_id",
    "workspace_id",
    "workspace_key_directory_checkpoint",
    "workspace_key_directory_checkpoint_ancestry",
    "workspace_key_directory_event_ancestry",
    "workspace_key_directory_events"
  ]

  @admission_commitment_field_names [
    "protocol",
    "protocol_version",
    "suite_id",
    "suite_rank",
    "purpose",
    "resource",
    "sender",
    "recipient",
    "event_scope",
    "event",
    "operation_checkpoint",
    "hpke",
    "transcript_hash"
  ]

  @wire_field_names @admission_commitment_field_names ++ ["signature"]
  @sender_schema [
    "device_id",
    "key_checkpoint_hash",
    "key_checkpoint_sequence",
    "key_scope_id",
    "key_scope_kind",
    "signer_kind",
    "signing_key_id",
    "user_id"
  ]
  @event_scope_schema ["scope_id", "scope_kind"]
  @resource_schemas %{
    "workspace_device_kek_wrap" => [
      "kek_version",
      "target_device_id",
      "target_user_id",
      "workspace_id"
    ],
    "workspace_member_kek_wrap" => ["kek_version", "target_user_id", "workspace_id"],
    "share_participant_bootstrap_wrap" => [
      "bootstrap_version",
      "dek_version",
      "document_scope_hash",
      "permission",
      "scope_id",
      "scope_kind",
      "share_id",
      "share_key_version",
      "share_participant_device_id",
      "share_participant_principal_id",
      "share_session_id",
      "workspace_id"
    ],
    "share_link_secret_backup_wrap" => [
      "created_event_hash",
      "key_checkpoint_hash",
      "password_capability_secret_commitment",
      "password_protected",
      "permission",
      "recipient_device_id",
      "recipient_encryption_key_id",
      "recipient_user_id",
      "scope_id",
      "scope_kind",
      "share_capability_secret_commitment",
      "share_id",
      "token_hash",
      "workspace_id",
      "workspace_pin_bootstrap_hash"
    ],
    "workspace_invitation_kek_wrap" => [
      "invitation_id",
      "kek_version",
      "recipient_encryption_key_id",
      "redeemed_device_id",
      "redeemed_user_id",
      "role_id",
      "workspace_id",
      "workspace_invitation_redeemed_event_hash"
    ],
    "guest_invitation_workspace_kek_wrap" => [
      "guest_device_id",
      "guest_grant_id",
      "guest_invitation_id",
      "guest_invitation_redeemed_event_hash",
      "guest_user_id",
      "kek_version",
      "permission",
      "recipient_encryption_key_id",
      "scope_id",
      "scope_kind",
      "workspace_id"
    ],
    "guest_invitation_share_key_wrap" => [
      "dek_version",
      "document_scope_hash",
      "guest_device_id",
      "guest_invitation_id",
      "guest_invitation_redeemed_event_hash",
      "guest_user_id",
      "permission",
      "recipient_encryption_key_id",
      "scope_id",
      "scope_kind",
      "share_id",
      "share_key_version",
      "workspace_id"
    ]
  }

  def attrs_from_params!(params) when is_map(params) do
    :ok = assert_wire_params!(params)
    params = normalize_wire_params(params)

    Enum.reduce(@string_fields ++ @integer_fields ++ @map_fields, %{}, fn field, acc ->
      Map.put(acc, field, Map.fetch!(params, Atom.to_string(field)))
    end)
    |> Map.merge(decoded_hpke_attrs!(params))
    |> Map.merge(decoded_signature_attrs!(params))
    |> Map.merge(decoded_binary_attrs!(params))
  end

  def attrs_from_container_params!(params) when is_map(params) do
    :ok = assert_container_params!(params)

    params
    |> Map.take(wire_field_names())
    |> attrs_from_params!()
  end

  def admission_commitment_hash!(params) when is_map(params) do
    params
    |> Map.take(@admission_commitment_field_names)
    |> then(fn commitment ->
      if Enum.sort(Map.keys(commitment)) == Enum.sort(@admission_commitment_field_names),
        do: commitment,
        else: raise(ArgumentError, "signed_pq_wrap_admission_commitment_invalid")
    end)
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  def response_fields(record) when is_map(record) do
    %{
      protocol: Map.fetch!(record, :wrap_protocol),
      protocol_version: Map.fetch!(record, :wrap_version),
      suite_id: Map.fetch!(record, :suite_id),
      suite_rank: Map.fetch!(record, :suite_rank),
      purpose: Map.fetch!(record, :purpose),
      resource: Map.fetch!(record, :resource),
      sender: Map.fetch!(record, :sender),
      recipient: Map.fetch!(record, :recipient),
      event_scope: Map.fetch!(record, :event_scope),
      event: %{
        wrap_event_sequence: Map.fetch!(record, :wrap_event_sequence),
        wrap_event_hash: Encoding.encode_base64url(Map.fetch!(record, :wrap_event_hash)),
        wrap_event_body_hash: Encoding.encode_base64url(Map.fetch!(record, :wrap_event_body_hash))
      },
      operation_checkpoint: %{
        checkpoint_sequence: Map.fetch!(record, :operation_checkpoint_sequence),
        checkpoint_hash:
          Encoding.encode_base64url(Map.fetch!(record, :operation_checkpoint_hash)),
        covered_event_head_sequence:
          Map.fetch!(record, :operation_checkpoint_covered_head_sequence),
        covered_event_head_hash:
          Encoding.encode_base64url(Map.fetch!(record, :operation_checkpoint_covered_head_hash))
      },
      hpke: %{
        mode: "base",
        kem_id: @kem_id,
        kdf_id: @kdf_id,
        aead_id: @aead_id,
        enc: Encoding.encode_base64url(Map.fetch!(record, :hpke_enc)),
        ciphertext: Encoding.encode_base64url(Map.fetch!(record, :hpke_ciphertext))
      },
      transcript_hash: Encoding.encode_base64url(Map.fetch!(record, :transcript_hash)),
      signature: %{
        protocol: Map.fetch!(record, :signature_protocol),
        version: Map.fetch!(record, :signature_version),
        suite_id: Map.fetch!(record, :signature_suite_id),
        suite_rank: Map.fetch!(record, :signature_suite_rank),
        signing_key_id: Encoding.encode_base64url(Map.fetch!(record, :sender_signing_key_id)),
        transcript_hash: Encoding.encode_base64url(Map.fetch!(record, :transcript_hash)),
        ed25519: Encoding.encode_base64url(Map.fetch!(record, :ed25519_signature)),
        mldsa65: Encoding.encode_base64url(Map.fetch!(record, :mldsa65_signature))
      }
    }
  end

  def validate_workspace_device_kek(attrs, context) when is_map(attrs) and is_map(context) do
    recipient_key_id = encode_binary(attrs.recipient_key_id)
    sender_signing_key_id = encode_binary(attrs.sender_signing_key_id)

    with :ok <- validate_common(attrs),
         :ok <- expect(attrs.purpose == "workspace_device_kek_wrap"),
         :ok <- validate_workspace_event_scope(attrs, context),
         :ok <- validate_workspace_kek_resource(attrs, context),
         :ok <- validate_workspace_kek_sender(attrs.sender, context, sender_signing_key_id),
         :ok <- validate_workspace_kek_recipient(attrs.recipient, context, recipient_key_id),
         :ok <- validate_wrap_event(attrs, context.key_directory_events) do
      :ok
    else
      {:error, _} -> {:error, :invalid_workspace_device_kek_wrap}
    end
  end

  def validate_workspace_member_kek(attrs, context) when is_map(attrs) and is_map(context) do
    recipient_key_id = encode_binary(attrs.recipient_key_id)
    sender_signing_key_id = encode_binary(attrs.sender_signing_key_id)

    with :ok <- validate_common(attrs),
         :ok <- expect(attrs.purpose == "workspace_member_kek_wrap"),
         :ok <- validate_workspace_event_scope(attrs, context),
         :ok <- validate_workspace_member_kek_resource(attrs, context),
         :ok <- validate_workspace_kek_sender(attrs.sender, context, sender_signing_key_id),
         :ok <-
           validate_workspace_member_kek_recipient(attrs.recipient, context, recipient_key_id),
         :ok <- validate_wrap_event(attrs, context.key_directory_events) do
      :ok
    else
      {:error, _} -> {:error, :invalid_workspace_member_kek_wrap}
    end
  end

  def validate_invitation_workspace_member_kek(attrs, context)
      when is_map(attrs) and is_map(context) do
    recipient_key_id = encode_binary(attrs.recipient_key_id)
    sender_signing_key_id = encode_binary(attrs.sender_signing_key_id)

    with :ok <- validate_common(attrs),
         :ok <- expect(attrs.purpose == "workspace_member_kek_wrap"),
         :ok <- validate_workspace_event_scope(attrs, context),
         :ok <- validate_workspace_member_kek_resource(attrs, context),
         :ok <- validate_workspace_kek_sender(attrs.sender, context, sender_signing_key_id),
         :ok <-
           validate_invitation_workspace_member_kek_recipient(
             attrs.recipient,
             context,
             recipient_key_id
           ),
         :ok <- validate_wrap_event(attrs, context.key_directory_events) do
      :ok
    else
      {:error, _} -> {:error, :invalid_workspace_member_kek_wrap}
    end
  end

  def validate_share_participant_bootstrap(attrs, context)
      when is_map(attrs) and is_map(context) do
    validate_scoped_wrap(
      attrs,
      context,
      "share_participant_bootstrap_wrap",
      :invalid_share_participant_bootstrap_wrap
    )
  end

  def validate_share_link_secret_backup(attrs, context) when is_map(attrs) and is_map(context) do
    validate_scoped_wrap(
      attrs,
      context,
      "share_link_secret_backup_wrap",
      :invalid_share_link_secret_backup_wrap
    )
  end

  def validate_workspace_invitation_kek(attrs, context) when is_map(attrs) and is_map(context) do
    validate_scoped_wrap(
      attrs,
      context,
      "workspace_invitation_kek_wrap",
      :invalid_workspace_invitation_kek_wrap
    )
  end

  def validate_guest_invitation_workspace_kek(attrs, context)
      when is_map(attrs) and is_map(context) do
    validate_scoped_wrap(
      attrs,
      context,
      "guest_invitation_workspace_kek_wrap",
      :invalid_guest_invitation_workspace_kek_wrap
    )
  end

  def validate_guest_invitation_share_key(attrs, context)
      when is_map(attrs) and is_map(context) do
    validate_scoped_wrap(
      attrs,
      context,
      "guest_invitation_share_key_wrap",
      :invalid_guest_invitation_share_key_wrap
    )
  end

  def validate_operation_checkpoint(attrs, checkpoint_payload, checkpoint_hash)
      when is_map(attrs) and is_map(checkpoint_payload) and is_binary(checkpoint_hash) do
    covered_head = Map.get(checkpoint_payload, "covered_event_head", %{})

    with :ok <- expect(attrs.operation_checkpoint_sequence == checkpoint_payload["sequence"]),
         :ok <- expect(encode_binary(attrs.operation_checkpoint_hash) == checkpoint_hash),
         :ok <-
           expect(
             attrs.operation_checkpoint_covered_head_sequence == covered_head["head_sequence"]
           ),
         :ok <-
           expect(
             encode_binary(attrs.operation_checkpoint_covered_head_hash) ==
               covered_head["head_hash"]
           ) do
      :ok
    else
      {:error, _} -> {:error, :operation_checkpoint_mismatch}
    end
  end

  def validate_operation_checkpoint(_attrs, _checkpoint_payload, _checkpoint_hash),
    do: {:error, :operation_checkpoint_mismatch}

  defp validate_scoped_wrap(attrs, context, purpose, error_reason) do
    with :ok <- validate_common(attrs),
         :ok <- expect(attrs.purpose == purpose),
         :ok <- validate_context_map(attrs.event_scope, context, :event_scope),
         :ok <- validate_context_map(attrs.resource, context, :resource),
         :ok <- validate_context_map(attrs.sender, context, :sender),
         :ok <- validate_context_map(attrs.recipient, context, :recipient),
         :ok <-
           validate_context_binary(attrs.sender_signing_key_id, context, :sender_signing_key_id),
         :ok <- validate_context_binary(attrs.recipient_key_id, context, :recipient_key_id),
         :ok <- validate_wrap_event(attrs, Map.get(context, :key_directory_events, [])) do
      :ok
    else
      {:error, _} -> {:error, error_reason}
    end
  end

  defp validate_context_map(actual, context, key) when is_map(actual) do
    case Map.fetch(context, key) do
      {:ok, expected} when is_map(expected) -> expect(actual == expected)
      _ -> {:error, :missing_context}
    end
  end

  defp validate_context_map(_actual, _context, _key), do: {:error, :missing_context}

  defp validate_context_binary(actual, context, key) when is_binary(actual) do
    case Map.fetch(context, key) do
      {:ok, expected} when is_binary(expected) -> expect(encode_binary(actual) == expected)
      _ -> {:error, :missing_context}
    end
  end

  defp validate_context_binary(_actual, _context, _key), do: {:error, :missing_context}

  defp validate_workspace_event_scope(attrs, context) do
    expect(
      attrs.event_scope == %{"scope_kind" => "workspace", "scope_id" => context.workspace_id}
    )
  end

  defp validate_workspace_kek_resource(attrs, context) do
    expect(
      attrs.resource == %{
        "workspace_id" => context.workspace_id,
        "target_user_id" => context.target_user_id,
        "target_device_id" => context.device_id,
        "kek_version" => context.key_version
      }
    )
  end

  defp validate_workspace_kek_sender(sender, context, sender_signing_key_id) do
    expect(
      Map.take(sender, [
        "signer_kind",
        "user_id",
        "device_id",
        "signing_key_id",
        "key_scope_kind",
        "key_scope_id",
        "key_checkpoint_sequence",
        "key_checkpoint_hash"
      ]) == %{
        "signer_kind" => "device",
        "user_id" => context.sender_user_id,
        "device_id" => context.sender_device_id,
        "signing_key_id" => sender_signing_key_id,
        "key_scope_kind" => "workspace",
        "key_scope_id" => context.workspace_id,
        "key_checkpoint_sequence" => context.key_checkpoint_sequence,
        "key_checkpoint_hash" => context.key_checkpoint_hash
      }
    )
  end

  defp validate_workspace_kek_recipient(recipient, context, recipient_key_id) do
    with :ok <- validate_recipient_keys(recipient) do
      expect(recipient == device_recipient(context, recipient_key_id))
    end
  end

  defp validate_workspace_member_kek_resource(attrs, context) do
    expect(
      attrs.resource == %{
        "workspace_id" => context.workspace_id,
        "target_user_id" => context.target_user_id,
        "kek_version" => context.key_version
      }
    )
  end

  defp validate_workspace_member_kek_recipient(recipient, context, recipient_key_id) do
    with :ok <- validate_recipient_keys(recipient) do
      expect(recipient == user_identity_recipient(context, recipient_key_id))
    end
  end

  defp validate_invitation_workspace_member_kek_recipient(
         recipient,
         %{recipient_key_scope_kind: "user"} = context,
         recipient_key_id
       ) do
    with :ok <- validate_recipient_keys(recipient) do
      expect(
        recipient == %{
          "recipient_kind" => "user_identity",
          "user_id" => context.target_user_id,
          "encryption_key_id" => recipient_key_id,
          "key_scope_kind" => "user",
          "key_scope_id" => context.target_user_id,
          "key_checkpoint_sequence" => context.recipient_key_checkpoint_sequence,
          "key_checkpoint_hash" => context.recipient_key_checkpoint_hash
        }
      )
    end
  end

  defp validate_recipient_keys(%{"recipient_kind" => kind} = recipient) when is_map(recipient) do
    common = [
      "encryption_key_id",
      "key_checkpoint_hash",
      "key_checkpoint_sequence",
      "key_scope_id",
      "key_scope_kind",
      "recipient_kind"
    ]

    keys =
      case kind do
        "device" ->
          common ++ ["device_id", "user_id"]

        "user_identity" ->
          common ++ ["user_id"]

        "invitee" ->
          common ++ ["invitee_device_id", "invitee_user_id"]

        "guest" ->
          common ++ ["guest_device_id", "guest_user_id"]

        "share_participant_device" ->
          common ++ ["share_participant_device_id", "share_participant_principal_id"]

        _ ->
          []
      end

    if keys != [] and Enum.sort(Map.keys(recipient)) == Enum.sort(keys),
      do: :ok,
      else: {:error, :recipient_schema_invalid}
  end

  defp validate_recipient_keys(_), do: {:error, :recipient_schema_invalid}

  defp device_recipient(context, recipient_key_id) do
    %{
      "recipient_kind" => "device",
      "user_id" => context.target_user_id,
      "device_id" => context.device_id,
      "encryption_key_id" => recipient_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => context.workspace_id,
      "key_checkpoint_sequence" => context.key_checkpoint_sequence,
      "key_checkpoint_hash" => context.key_checkpoint_hash
    }
  end

  defp user_identity_recipient(context, recipient_key_id) do
    %{
      "recipient_kind" => "user_identity",
      "user_id" => context.target_user_id,
      "encryption_key_id" => recipient_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => context.workspace_id,
      "key_checkpoint_sequence" => context.key_checkpoint_sequence,
      "key_checkpoint_hash" => context.key_checkpoint_hash
    }
  end

  def validate_wrap_event(attrs, events) when is_list(events) do
    case Enum.find(events, &matching_wrap_event?(&1, attrs)) do
      %{"payload" => %{"body" => body}} when is_map(body) ->
        validate_wrap_event_body(attrs, body)

      _ ->
        {:error, :wrap_event_missing}
    end
  end

  def validate_wrap_event(_, _), do: {:error, :wrap_event_missing}

  defp matching_wrap_event?(
         %{
           "payload" =>
             %{
               "event_type" => "wrap_issued",
               "sequence" => sequence
             } = payload
         },
         attrs
       ) do
    sequence == attrs.wrap_event_sequence and
      Hash.blake3_base64url(JCS.canonical_bytes!(payload)) == encode_binary(attrs.wrap_event_hash)
  rescue
    _ -> false
  end

  defp matching_wrap_event?(_, _), do: false

  defp validate_wrap_event_body(attrs, body) do
    expected = %{
      "purpose" => attrs.purpose,
      "resource" => attrs.resource,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender" => attrs.sender,
      "recipient" => attrs.recipient,
      "wrap_body_hash" => encode_binary(attrs.wrap_body_hash),
      "wrap_protocol" => attrs.wrap_protocol,
      "wrap_suite_id" => attrs.suite_id,
      "wrap_suite_rank" => attrs.suite_rank,
      "wrap_version" => attrs.wrap_version
    }

    if body == expected do
      :ok
    else
      {:error, :wrap_event_mismatch}
    end
  end

  def verify_signature(attrs, sender_signing_public_key_material)
      when is_map(attrs) and is_map(sender_signing_public_key_material) do
    with :ok <- validate_common(attrs),
         :ok <- validate_body_hash(attrs),
         :ok <- validate_event_hashes(attrs),
         true <-
           Signature.verify_hybrid_signature(
             "pq_wrap",
             Signature.build_pq_wrap_transcript!(
               attrs.sender["device_id"],
               attrs.sender,
               authority_boundary(attrs),
               subject_hashes(attrs)
             ),
             signature(attrs),
             sender_signing_public_key_material
           ) do
      :ok
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp decoded_binary_attrs!(params) do
    Enum.reduce(@binary_fields, %{}, fn field, acc ->
      Map.put(
        acc,
        Map.fetch!(@binary_field_atoms, field),
        Encoding.decode_base64url!(Map.fetch!(params, field))
      )
    end)
  end

  defp assert_wire_params!(params) do
    if Enum.sort(Map.keys(params)) == Enum.sort(wire_field_names()),
      do: :ok,
      else: raise(ArgumentError, "signed_pq_wrap_schema_invalid")
  end

  defp assert_container_params!(params) do
    allowed = wire_field_names() ++ @container_field_names

    if Enum.all?(Map.keys(params), &(&1 in allowed)),
      do: :ok,
      else: raise(ArgumentError, "signed_pq_wrap_schema_invalid")
  end

  defp wire_field_names do
    @wire_field_names
  end

  defp normalize_wire_params(%{"hpke" => hpke, "signature" => signature} = params)
       when is_map(hpke) and is_map(signature) do
    assert_exact_nested_keys!(
      Map.fetch!(params, "resource"),
      Map.fetch!(@resource_schemas, Map.fetch!(params, "purpose"))
    )

    assert_exact_nested_keys!(Map.fetch!(params, "sender"), @sender_schema)
    assert_exact_recipient_keys!(Map.fetch!(params, "recipient"))
    assert_exact_nested_keys!(Map.fetch!(params, "event_scope"), @event_scope_schema)
    assert_exact_nested_keys!(hpke, ["aead_id", "ciphertext", "enc", "kdf_id", "kem_id", "mode"])

    assert_exact_nested_keys!(Map.fetch!(params, "event"), [
      "wrap_event_body_hash",
      "wrap_event_hash",
      "wrap_event_sequence"
    ])

    assert_exact_nested_keys!(Map.fetch!(params, "operation_checkpoint"), [
      "checkpoint_hash",
      "checkpoint_sequence",
      "covered_event_head_hash",
      "covered_event_head_sequence"
    ])

    assert_exact_nested_keys!(signature, [
      "ed25519",
      "mldsa65",
      "protocol",
      "signing_key_id",
      "suite_id",
      "suite_rank",
      "transcript_hash",
      "version"
    ])

    if hpke["mode"] != "base" or hpke["kem_id"] != @kem_id or hpke["kdf_id"] != @kdf_id or
         hpke["aead_id"] != @aead_id or
         params["sender"]["signing_key_id"] != signature["signing_key_id"] or
         params["transcript_hash"] != signature["transcript_hash"] do
      raise ArgumentError, "signed_pq_wrap_schema_invalid"
    end

    event = params["event"]
    checkpoint = params["operation_checkpoint"]
    wrap_body_hash = wire_wrap_body_hash!(params)

    params
    |> Map.put("wrap_protocol", params["protocol"])
    |> Map.put("wrap_version", params["protocol_version"])
    |> Map.put("kem_id", hpke["kem_id"])
    |> Map.put("kdf_id", hpke["kdf_id"])
    |> Map.put("aead_id", hpke["aead_id"])
    |> Map.put("wrap_event_sequence", event["wrap_event_sequence"])
    |> Map.put("wrap_event_hash", event["wrap_event_hash"])
    |> Map.put("wrap_event_body_hash", event["wrap_event_body_hash"])
    |> Map.put("operation_checkpoint_sequence", checkpoint["checkpoint_sequence"])
    |> Map.put("operation_checkpoint_hash", checkpoint["checkpoint_hash"])
    |> Map.put(
      "operation_checkpoint_covered_head_sequence",
      checkpoint["covered_event_head_sequence"]
    )
    |> Map.put("operation_checkpoint_covered_head_hash", checkpoint["covered_event_head_hash"])
    |> Map.put("wrap_body_hash", wrap_body_hash)
    |> Map.put("recipient_key_id", params["recipient"]["encryption_key_id"])
    |> Map.put("sender_signing_key_id", params["sender"]["signing_key_id"])
    |> Map.put("transcript_hash", signature["transcript_hash"])
    |> Map.put("ed25519_signature", signature["ed25519"])
    |> Map.put("mldsa65_signature", signature["mldsa65"])
  end

  defp normalize_wire_params(_params), do: raise(ArgumentError, "signed_pq_wrap_schema_invalid")

  defp wire_wrap_body_hash!(params) do
    params
    |> wire_wrap_body()
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  defp wire_wrap_body(params) do
    hpke = Map.fetch!(params, "hpke")

    %{
      "label" => "RefMD PQ wrap body v1",
      "protocol" => @wrap_protocol,
      "version" => params["protocol_version"],
      "suite_id" => params["suite_id"],
      "suite_rank" => params["suite_rank"],
      "purpose" => params["purpose"],
      "resource" => params["resource"],
      "sender" => params["sender"],
      "recipient" => params["recipient"],
      "event_scope" => params["event_scope"],
      "hpke" => %{
        "mode" => "base",
        "kem_id" => @kem_id,
        "kdf_id" => @kdf_id,
        "aead_id" => @aead_id,
        "enc" => hpke["enc"],
        "ciphertext" => hpke["ciphertext"]
      },
      "hpke_info_hash" => Hash.blake3_base64url(wire_hpke_info(params)),
      "aad_hash" => Hash.blake3_base64url(wire_aad(params))
    }
  end

  defp wire_hpke_info(params) do
    sender = Map.fetch!(params, "sender")
    recipient = Map.fetch!(params, "recipient")
    event_scope = Map.fetch!(params, "event_scope")

    JCS.canonical_bytes!(%{
      "label" => "RefMD HPKE info v1",
      "protocol" => @wrap_protocol,
      "protocol_version" => params["protocol_version"],
      "suite_id" => params["suite_id"],
      "suite_rank" => params["suite_rank"],
      "purpose" => params["purpose"],
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(params["resource"])),
      "sender_user_id" => sender["user_id"],
      "sender_device_id" => sender["device_id"],
      "sender_signing_key_id" => sender["signing_key_id"],
      "sender_key_scope_kind" => sender["key_scope_kind"],
      "sender_key_scope_id" => sender["key_scope_id"],
      "sender_key_checkpoint_hash" => sender["key_checkpoint_hash"],
      "recipient_kind" => recipient["recipient_kind"],
      "recipient_key_id" => recipient["encryption_key_id"],
      "recipient_key_scope_kind" => recipient["key_scope_kind"],
      "recipient_key_scope_id" => recipient["key_scope_id"],
      "recipient_key_checkpoint_hash" => recipient["key_checkpoint_hash"],
      "event_scope_kind" => event_scope["scope_kind"],
      "event_scope_id" => event_scope["scope_id"]
    })
  end

  defp wire_aad(params) do
    hpke = Map.fetch!(params, "hpke")

    JCS.canonical_bytes!(%{
      "label" => "RefMD PQ wrap AAD v1",
      "protocol" => @wrap_protocol,
      "protocol_version" => params["protocol_version"],
      "suite_id" => params["suite_id"],
      "suite_rank" => params["suite_rank"],
      "purpose" => params["purpose"],
      "resource" => params["resource"],
      "sender" => params["sender"],
      "recipient" => params["recipient"],
      "event_scope" => params["event_scope"],
      "hpke" => %{
        "mode" => "base",
        "kem_id" => @kem_id,
        "kdf_id" => @kdf_id,
        "aead_id" => @aead_id,
        "enc" => hpke["enc"]
      }
    })
  end

  defp assert_exact_nested_keys!(value, keys) when is_map(value) do
    if Enum.sort(Map.keys(value)) == Enum.sort(keys),
      do: :ok,
      else: raise(ArgumentError, "signed_pq_wrap_schema_invalid")
  end

  defp assert_exact_nested_keys!(_value, _keys),
    do: raise(ArgumentError, "signed_pq_wrap_schema_invalid")

  defp assert_exact_recipient_keys!(%{"recipient_kind" => kind} = recipient) do
    common = [
      "encryption_key_id",
      "key_checkpoint_hash",
      "key_checkpoint_sequence",
      "key_scope_id",
      "key_scope_kind",
      "recipient_kind"
    ]

    keys =
      case kind do
        "device" ->
          common ++ ["device_id", "user_id"]

        "user_identity" ->
          common ++ ["user_id"]

        "invitee" ->
          common ++ ["invitee_device_id", "invitee_user_id"]

        "guest" ->
          common ++ ["guest_device_id", "guest_user_id"]

        "share_participant_device" ->
          common ++ ["share_participant_device_id", "share_participant_principal_id"]

        _ ->
          raise ArgumentError, "signed_pq_wrap_schema_invalid"
      end

    assert_exact_nested_keys!(recipient, keys)
  end

  defp assert_exact_recipient_keys!(_recipient),
    do: raise(ArgumentError, "signed_pq_wrap_schema_invalid")

  defp decoded_hpke_attrs!(%{"hpke" => hpke}) when is_map(hpke) do
    case hpke do
      %{"mode" => "base", "kem_id" => @kem_id, "kdf_id" => @kdf_id, "aead_id" => @aead_id} ->
        %{
          hpke_enc: Encoding.decode_base64url!(Map.fetch!(hpke, "enc"), @hpke_enc_bytes),
          hpke_ciphertext: Encoding.decode_base64url!(Map.fetch!(hpke, "ciphertext"))
        }

      _ ->
        raise ArgumentError, "signed_pq_wrap_hpke_invalid"
    end
  end

  defp decoded_hpke_attrs!(_params), do: raise(ArgumentError, "signed_pq_wrap_hpke_invalid")

  defp decoded_signature_attrs!(%{"signature" => signature}) when is_map(signature) do
    %{
      signature_protocol: Map.fetch!(signature, "protocol"),
      signature_version: Map.fetch!(signature, "version"),
      signature_suite_id: Map.fetch!(signature, "suite_id"),
      signature_suite_rank: Map.fetch!(signature, "suite_rank"),
      transcript_hash: Encoding.decode_base64url!(Map.fetch!(signature, "transcript_hash")),
      ed25519_signature:
        Encoding.decode_base64url!(Map.fetch!(signature, "ed25519"), @ed25519_signature_bytes),
      mldsa65_signature:
        Encoding.decode_base64url!(Map.fetch!(signature, "mldsa65"), @mldsa65_signature_bytes)
    }
  end

  defp decoded_signature_attrs!(_params),
    do: raise(ArgumentError, "signed_pq_wrap_signature_invalid")

  defp validate_common(attrs) do
    with :ok <- expect(attrs.wrap_protocol == @wrap_protocol),
         :ok <- expect(attrs.kem_id == @kem_id),
         :ok <- expect(attrs.kdf_id == @kdf_id),
         :ok <- expect(attrs.aead_id == @aead_id),
         :ok <- expect(byte_size(attrs.hpke_enc) == @hpke_enc_bytes),
         :ok <- expect(byte_size(attrs.ed25519_signature) == @ed25519_signature_bytes),
         :ok <- expect(byte_size(attrs.mldsa65_signature) == @mldsa65_signature_bytes),
         :ok <- expect(attrs.signature_protocol == @signature_protocol),
         :ok <- expect(attrs.signature_suite_id == @signature_suite_id),
         :ok <- validate_sender_schema(attrs.sender),
         :ok <- validate_recipient_keys(attrs.recipient),
         :ok <- validate_event_scope_schema(attrs.event_scope),
         :ok <- validate_resource_schema(attrs.purpose, attrs.resource) do
      Suite.assert_protocol_version!(attrs.wrap_version)
      Suite.assert_suite_rank_allowed!(attrs.suite_id, attrs.suite_rank)
      if attrs.suite_id != @wrap_suite_id, do: raise(ArgumentError, "suite_id_invalid")
      Suite.assert_protocol_version!(attrs.signature_version)
      Suite.assert_suite_rank_allowed!(attrs.signature_suite_id, attrs.signature_suite_rank)
      :ok
    end
  rescue
    ArgumentError -> {:error, :suite_invalid}
  end

  defp expect(true), do: :ok
  defp expect(false), do: {:error, :expectation_failed}

  defp validate_resource_schema(purpose, resource)
       when is_binary(purpose) and is_map(resource) do
    with keys when is_list(keys) <- Map.get(@resource_schemas, purpose),
         :ok <- expect(Enum.sort(Map.keys(resource)) == keys),
         :ok <- validate_resource_values(purpose, resource, keys) do
      :ok
    else
      _ -> {:error, :invalid_resource_schema}
    end
  end

  defp validate_resource_schema(_, _), do: {:error, :invalid_resource_schema}

  defp validate_sender_schema(%{"signer_kind" => "device"} = sender)
       when is_map(sender) do
    if Enum.sort(Map.keys(sender)) == @sender_schema,
      do: :ok,
      else: {:error, :sender_schema_invalid}
  end

  defp validate_sender_schema(_sender), do: {:error, :sender_schema_invalid}

  defp validate_event_scope_schema(event_scope) when is_map(event_scope) do
    if Enum.sort(Map.keys(event_scope)) == @event_scope_schema,
      do: :ok,
      else: {:error, :event_scope_schema_invalid}
  end

  defp validate_event_scope_schema(_event_scope), do: {:error, :event_scope_schema_invalid}

  defp validate_resource_values(purpose, resource, keys) do
    Enum.reduce_while(keys, :ok, fn key, :ok ->
      case valid_resource_value?(key, resource[key]) do
        true -> {:cont, :ok}
        false -> {:halt, {:error, :invalid_resource_value}}
      end
    end)
    |> case do
      :ok -> validate_resource_semantics(purpose, resource)
      error -> error
    end
  end

  defp valid_resource_value?("password_protected", value), do: is_boolean(value)

  defp valid_resource_value?(key, value)
       when key in ["kek_version", "share_key_version", "dek_version", "bootstrap_version"],
       do: is_integer(value) and value > 0

  defp valid_resource_value?(_, value), do: is_binary(value) and value != ""

  defp validate_resource_semantics("guest_invitation_workspace_kek_wrap", resource) do
    expect(resource["scope_kind"] == "workspace" and resource["scope_id"] == "none")
  end

  defp validate_resource_semantics(purpose, resource)
       when purpose in [
              "share_participant_bootstrap_wrap",
              "share_link_secret_backup_wrap",
              "guest_invitation_share_key_wrap"
            ] do
    case expect(
           resource["scope_kind"] in ["document", "folder"] and
             resource["permission"] in ["view", "edit"] and resource["scope_id"] != "none"
         ) do
      :ok ->
        resource
        |> validate_share_resource_ids()
        |> then_ok(fn -> validate_share_resource_hashes(resource) end)

      error ->
        error
    end
  end

  defp validate_resource_semantics(_purpose, resource) do
    cond do
      Map.has_key?(resource, "scope_kind") and
          resource["scope_kind"] not in ["document", "folder", "workspace"] ->
        {:error, :invalid_resource_scope}

      Map.has_key?(resource, "permission") and resource["permission"] not in ["view", "edit"] ->
        {:error, :invalid_resource_permission}

      true ->
        :ok
    end
  end

  defp validate_share_resource_ids(resource) do
    [
      "workspace_id",
      "share_id",
      "scope_id",
      "guest_invitation_id",
      "guest_user_id",
      "guest_device_id",
      "recipient_device_id",
      "recipient_user_id",
      "share_participant_device_id",
      "share_participant_principal_id",
      "share_session_id"
    ]
    |> Enum.reduce_while(:ok, fn key, :ok ->
      case Map.fetch(resource, key) do
        {:ok, "none"} -> {:halt, {:error, :invalid_resource_id}}
        _ -> {:cont, :ok}
      end
    end)
  end

  defp validate_share_resource_hashes(resource) do
    [
      "document_scope_hash",
      "created_event_hash",
      "key_checkpoint_hash",
      "share_capability_secret_commitment",
      "token_hash",
      "workspace_pin_bootstrap_hash",
      "guest_invitation_redeemed_event_hash"
    ]
    |> Enum.reduce_while(:ok, fn key, :ok ->
      reduce_share_resource_hash(resource, key)
    end)
    |> then_ok(fn -> validate_password_capability_commitment(resource) end)
  end

  defp reduce_share_resource_hash(resource, key) do
    case Map.fetch(resource, key) do
      {:ok, value} when is_binary(value) -> reduce_share_resource_hash_value(value)
      {:ok, _} -> {:halt, {:error, :invalid_resource_hash}}
      :error -> {:cont, :ok}
    end
  end

  defp validate_password_capability_commitment(resource) do
    case Map.fetch(resource, "password_capability_secret_commitment") do
      {:ok, "none"} -> expect(resource["password_protected"] == false)
      {:ok, value} when is_binary(value) -> validate_share_resource_hash_value(value)
      {:ok, _} -> {:error, :invalid_resource_hash}
      :error -> :ok
    end
  end

  defp reduce_share_resource_hash_value(value) do
    if Regex.match?(~r/^[A-Za-z0-9_-]{43}$/, value),
      do: {:cont, :ok},
      else: {:halt, {:error, :invalid_resource_hash}}
  end

  defp validate_share_resource_hash_value(value) do
    if Regex.match?(~r/^[A-Za-z0-9_-]{43}$/, value),
      do: :ok,
      else: {:error, :invalid_resource_hash}
  end

  defp then_ok(:ok, fun), do: fun.()
  defp then_ok(error, _fun), do: error

  defp encode_binary(value) when is_binary(value), do: Encoding.encode_base64url(value)

  defp validate_body_hash(attrs) do
    body = %{
      "label" => "RefMD PQ wrap body v1",
      "protocol" => @wrap_protocol,
      "version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource" => attrs.resource,
      "sender" => attrs.sender,
      "recipient" => attrs.recipient,
      "event_scope" => attrs.event_scope,
      "hpke" => %{
        "mode" => "base",
        "kem_id" => attrs.kem_id,
        "kdf_id" => attrs.kdf_id,
        "aead_id" => attrs.aead_id,
        "enc" => encode_binary(attrs.hpke_enc),
        "ciphertext" => encode_binary(attrs.hpke_ciphertext)
      },
      "hpke_info_hash" => Hash.blake3_base64url(hpke_info(attrs)),
      "aad_hash" => Hash.blake3_base64url(wrap_aad(attrs))
    }

    if Hash.blake3_base64url(JCS.canonical_bytes!(body)) == encode_binary(attrs.wrap_body_hash),
      do: :ok,
      else: {:error, :wrap_body_hash_mismatch}
  end

  defp validate_event_hashes(attrs) do
    event_body = wrap_event_body(attrs)
    event_body_hash = Hash.blake3_base64url(JCS.canonical_bytes!(event_body))

    cond do
      event_body_hash != encode_binary(attrs.wrap_event_body_hash) ->
        {:error, :wrap_event_body_hash_mismatch}

      attrs.operation_checkpoint_covered_head_sequence < attrs.wrap_event_sequence ->
        {:error, :operation_checkpoint_does_not_cover_wrap_event}

      attrs.operation_checkpoint_covered_head_sequence == attrs.wrap_event_sequence and
          encode_binary(attrs.operation_checkpoint_covered_head_hash) !=
            encode_binary(attrs.wrap_event_hash) ->
        {:error, :operation_checkpoint_head_mismatch}

      true ->
        :ok
    end
  end

  defp wrap_event_body(attrs) do
    %{
      "purpose" => attrs.purpose,
      "recipient" => attrs.recipient,
      "resource" => attrs.resource,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender" => attrs.sender,
      "wrap_body_hash" => encode_binary(attrs.wrap_body_hash),
      "wrap_protocol" => attrs.wrap_protocol,
      "wrap_suite_id" => attrs.suite_id,
      "wrap_suite_rank" => attrs.suite_rank,
      "wrap_version" => attrs.wrap_version
    }
  end

  defp authority_boundary(attrs) do
    %{
      "scope_kind" => attrs.event_scope["scope_kind"],
      "scope_id" => attrs.event_scope["scope_id"],
      "event_hash" => encode_binary(attrs.wrap_event_hash),
      "operation_checkpoint_sequence" => attrs.operation_checkpoint_sequence,
      "operation_checkpoint_hash" => encode_binary(attrs.operation_checkpoint_hash),
      "covered_event_head_sequence" => attrs.operation_checkpoint_covered_head_sequence,
      "covered_event_head_hash" => encode_binary(attrs.operation_checkpoint_covered_head_hash)
    }
  end

  defp subject_hashes(attrs) do
    %{
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "wrap_body_hash" => encode_binary(attrs.wrap_body_hash),
      "wrap_event_body_hash" => encode_binary(attrs.wrap_event_body_hash),
      "wrap_event_hash" => encode_binary(attrs.wrap_event_hash),
      "hpke_info_hash" => Hash.blake3_base64url(hpke_info(attrs)),
      "aad_hash" => Hash.blake3_base64url(wrap_aad(attrs))
    }
  end

  defp hpke_info(attrs) do
    JCS.canonical_bytes!(%{
      "label" => "RefMD HPKE info v1",
      "protocol" => @wrap_protocol,
      "protocol_version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender_user_id" => attrs.sender["user_id"],
      "sender_device_id" => attrs.sender["device_id"],
      "sender_signing_key_id" => attrs.sender["signing_key_id"],
      "sender_key_scope_kind" => attrs.sender["key_scope_kind"],
      "sender_key_scope_id" => attrs.sender["key_scope_id"],
      "sender_key_checkpoint_hash" => attrs.sender["key_checkpoint_hash"],
      "recipient_kind" => attrs.recipient["recipient_kind"],
      "recipient_key_id" => attrs.recipient["encryption_key_id"],
      "recipient_key_scope_kind" => attrs.recipient["key_scope_kind"],
      "recipient_key_scope_id" => attrs.recipient["key_scope_id"],
      "recipient_key_checkpoint_hash" => attrs.recipient["key_checkpoint_hash"],
      "event_scope_kind" => attrs.event_scope["scope_kind"],
      "event_scope_id" => attrs.event_scope["scope_id"]
    })
  end

  defp wrap_aad(attrs) do
    JCS.canonical_bytes!(%{
      "label" => "RefMD PQ wrap AAD v1",
      "protocol" => @wrap_protocol,
      "protocol_version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource" => attrs.resource,
      "sender" => attrs.sender,
      "recipient" => attrs.recipient,
      "event_scope" => attrs.event_scope,
      "hpke" => %{
        "mode" => "base",
        "kem_id" => attrs.kem_id,
        "kdf_id" => attrs.kdf_id,
        "aead_id" => attrs.aead_id,
        "enc" => encode_binary(attrs.hpke_enc)
      }
    })
  end

  defp signature(attrs) do
    %{
      "protocol" => attrs.signature_protocol,
      "version" => attrs.signature_version,
      "suite_id" => attrs.signature_suite_id,
      "suite_rank" => attrs.signature_suite_rank,
      "signing_key_id" => encode_binary(attrs.sender_signing_key_id),
      "transcript_hash" => encode_binary(attrs.transcript_hash),
      "ed25519" => encode_binary(attrs.ed25519_signature),
      "mldsa65" => encode_binary(attrs.mldsa65_signature)
    }
  end
end
