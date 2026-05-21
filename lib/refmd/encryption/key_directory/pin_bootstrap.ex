defmodule RefMD.Encryption.KeyDirectory.PinBootstrap do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Encryption.KeyDirectory.{Authority, Event, Protocol, State}
  alias RefMD.Repo

  @max_safe_json_integer 9_007_199_254_740_991
  @base64url_re ~r/^[A-Za-z0-9_-]+$/
  @envelope_keys Enum.sort(["payload", "signatures"])
  @payload_keys Enum.sort([
                  "allowed_suite_ids_hash",
                  "bootstrap_nonce",
                  "checkpoint_hash",
                  "checkpoint_sequence",
                  "event_head_hash",
                  "event_head_sequence",
                  "expires_event_sequence",
                  "issuer",
                  "issuing_event_hash",
                  "min_suite_rank",
                  "protocol",
                  "suite_policy_version",
                  "version",
                  "workspace_id"
                ])
  @issuer_keys Enum.sort([
                 "device_id",
                 "key_checkpoint_hash",
                 "key_checkpoint_sequence",
                 "key_scope_id",
                 "key_scope_kind",
                 "signer_kind",
                 "signing_key_id",
                 "user_id"
               ])
  @signature_envelope_keys Enum.sort(["signature", "signer"])

  @spec hash!(Ecto.UUID.t(), map()) :: binary()
  def hash!(workspace_id, %{"payload" => payload, "signatures" => signatures} = bootstrap)
      when is_binary(workspace_id) and is_map(payload) and is_list(signatures) do
    assert_exact_keys!(bootstrap, @envelope_keys, "workspace_pin_bootstrap_invalid")
    assert_signature_envelopes!(signatures)
    validate_payload!(workspace_id, payload)
    Hash.blake3_base64url(JCS.canonical_bytes!(payload))
  end

  def hash!(_, _), do: raise(ArgumentError, "workspace_pin_bootstrap_invalid")

  @spec validate!(Ecto.UUID.t(), map(), map() | struct(), pos_integer()) :: :ok
  def validate!(
        workspace_id,
        %{"payload" => payload, "signatures" => signatures} = bootstrap,
        checkpoint,
        operation_sequence
      )
      when is_binary(workspace_id) and is_map(payload) and is_list(signatures) do
    checkpoint_payload = checkpoint_payload!(checkpoint)

    hash!(workspace_id, bootstrap)
    assert_not_expired!(payload, operation_sequence)
    assert_checkpoint_binding!(workspace_id, payload, checkpoint_payload)
    assert_issuing_event_authority!(workspace_id, payload)
    assert_signature!(workspace_id, payload, signatures, checkpoint_payload)
  end

  def validate!(_, _, _, _), do: raise(ArgumentError, "workspace_pin_bootstrap_invalid")

  defp validate_payload!(workspace_id, payload) do
    assert_exact_keys!(payload, @payload_keys, "workspace_pin_payload_invalid")
    issuer = required_map!(payload, "issuer")
    assert_payload_header!(workspace_id, payload)
    assert_payload_numbers!(payload)
    assert_payload_hashes!(payload)
    assert_issuer!(workspace_id, issuer)
  end

  defp assert_payload_header!(workspace_id, payload) do
    unless payload["protocol"] == "refmd.workspace-pin-bootstrap" and
             payload["version"] == 1 and
             payload["workspace_id"] == workspace_id do
      raise ArgumentError, "workspace_pin_payload_invalid"
    end
  end

  defp assert_payload_numbers!(payload) do
    unless required_integer!(payload, "checkpoint_sequence") > 0 and
             required_integer!(payload, "event_head_sequence") >= 0 and
             required_integer!(payload, "suite_policy_version") > 0 and
             required_integer!(payload, "min_suite_rank") > 0 and
             required_integer!(payload, "expires_event_sequence") <= @max_safe_json_integer do
      raise ArgumentError, "workspace_pin_payload_invalid"
    end
  end

  defp assert_payload_hashes!(payload) do
    for key <- [
          "checkpoint_hash",
          "event_head_hash",
          "allowed_suite_ids_hash",
          "issuing_event_hash"
        ],
        do: required_blake3_hash!(payload, key)

    required_base64url_32!(payload, "bootstrap_nonce")
  end

  defp assert_issuer!(workspace_id, issuer) do
    assert_exact_keys!(issuer, @issuer_keys, "workspace_pin_payload_invalid")

    unless issuer["signer_kind"] == "device" and
             issuer["key_scope_kind"] == "workspace" and
             issuer["key_scope_id"] == workspace_id do
      raise ArgumentError, "workspace_pin_payload_invalid"
    end

    required_string!(issuer, "user_id")
    required_string!(issuer, "device_id")
    required_string!(issuer, "signing_key_id")
    required_integer!(issuer, "key_checkpoint_sequence")
    required_string!(issuer, "key_checkpoint_hash")
  end

  defp checkpoint_payload!(%{payload: payload}) when is_map(payload), do: payload

  defp checkpoint_payload!(%{"payload" => payload}) when is_map(payload), do: payload

  defp checkpoint_payload!(_), do: raise(ArgumentError, "workspace_pin_checkpoint_invalid")

  defp assert_checkpoint_binding!(workspace_id, payload, checkpoint_payload) do
    covered_head = required_map!(checkpoint_payload, "covered_event_head")
    checkpoint_hash = Protocol.checkpoint_hash(checkpoint_payload)

    checks = [
      payload["workspace_id"] == workspace_id,
      payload["checkpoint_sequence"] == checkpoint_payload["sequence"],
      payload["checkpoint_hash"] == checkpoint_hash,
      payload["event_head_sequence"] == covered_head["head_sequence"],
      payload["event_head_hash"] == covered_head["head_hash"],
      payload["suite_policy_version"] == checkpoint_payload["suite_policy_version"],
      payload["min_suite_rank"] == checkpoint_payload["min_suite_rank"],
      payload["allowed_suite_ids_hash"] == allowed_suite_ids_hash!(checkpoint_payload),
      required_map!(payload, "issuer")["key_checkpoint_sequence"] ==
        payload["checkpoint_sequence"],
      required_map!(payload, "issuer")["key_checkpoint_hash"] == payload["checkpoint_hash"]
    ]

    unless Enum.all?(checks), do: raise(ArgumentError, "workspace_pin_checkpoint_mismatch")
  end

  defp assert_not_expired!(payload, operation_sequence)
       when is_integer(operation_sequence) and operation_sequence >= 1 do
    if required_integer!(payload, "expires_event_sequence") < operation_sequence do
      raise ArgumentError, "workspace_pin_bootstrap_expired"
    end

    :ok
  end

  defp assert_not_expired!(_, _), do: raise(ArgumentError, "workspace_pin_operation_invalid")

  defp assert_issuing_event_authority!(workspace_id, payload) do
    issuer = required_map!(payload, "issuer")
    event_head_sequence = required_integer!(payload, "event_head_sequence")
    event_hash = required_string!(payload, "issuing_event_hash")

    event =
      Event
      |> where(
        [e],
        e.scope_kind == "workspace" and e.scope_id == ^workspace_id and
          e.sequence <= ^event_head_sequence and e.event_hash == ^event_hash
      )
      |> order_by([e], desc: e.sequence)
      |> Repo.one()

    case event do
      %Event{} ->
        Authority.assert_event_authority!(event.payload)

        Authority.assert_workspace_pin_bootstrap_issuer_authority!(
          workspace_id,
          event_head_sequence,
          issuer
        )

      _ ->
        raise ArgumentError, "workspace_pin_issuing_event_missing"
    end
  end

  defp assert_signature!(workspace_id, payload, signatures, checkpoint_payload) do
    issuer = required_map!(payload, "issuer")
    signing_key_id = required_string!(issuer, "signing_key_id")

    State.assert_key_entry_active_at_sequence!(
      checkpoint_payload,
      signing_key_id,
      required_integer!(payload, "event_head_sequence")
    )

    material =
      checkpoint_payload
      |> State.key_entry_by_id!(signing_key_id)
      |> Map.fetch!("key_material")

    assert_material_matches_issuer!(material, issuer)
    signature = signature_for_issuer!(signatures, signing_key_id)

    transcript =
      Signature.build_workspace_pin_bootstrap_transcript!(
        required_string!(issuer, "device_id"),
        workspace_id,
        payload
      )

    unless Signature.verify_hybrid_signature(
             "workspace_pin_bootstrap",
             transcript,
             signature,
             material,
             %{bootstrap: payload}
           ) do
      raise ArgumentError, "workspace_pin_signature_invalid"
    end

    :ok
  end

  defp assert_material_matches_issuer!(material, issuer) when is_map(material) do
    checks = [
      material["owner_kind"] == "device",
      material["owner_id"] == issuer["device_id"],
      Signature.compute_signing_key_id!(material) == issuer["signing_key_id"]
    ]

    unless Enum.all?(checks), do: raise(ArgumentError, "workspace_pin_issuer_mismatch")
  end

  defp assert_material_matches_issuer!(_, _),
    do: raise(ArgumentError, "workspace_pin_issuer_mismatch")

  defp signature_for_issuer!(signatures, signing_key_id) do
    Enum.find_value(signatures, fn
      %{
        "signer" => %{"signer_kind" => "device", "signing_key_id" => ^signing_key_id},
        "signature" => signature
      }
      when is_map(signature) ->
        signature

      _ ->
        nil
    end) || raise(ArgumentError, "workspace_pin_signature_missing")
  end

  defp allowed_suite_ids_hash!(checkpoint_payload) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "allowed_suite_ids" => Map.fetch!(checkpoint_payload, "allowed_suite_ids")
      })
    )
  end

  defp required_map!(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_map(value) -> value
      _ -> raise(ArgumentError, "workspace_pin_payload_invalid")
    end
  end

  defp required_integer!(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_integer(value) -> value
      _ -> raise(ArgumentError, "workspace_pin_payload_invalid")
    end
  end

  defp required_string!(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) and value != "" -> value
      _ -> raise(ArgumentError, "workspace_pin_payload_invalid")
    end
  end

  defp required_blake3_hash!(map, key) do
    value = required_string!(map, key)

    if base64url_32?(value) do
      value
    else
      raise ArgumentError, "workspace_pin_payload_invalid"
    end
  end

  defp required_base64url_32!(map, key) do
    value = required_string!(map, key)

    if base64url_32?(value) do
      value
    else
      raise ArgumentError, "workspace_pin_payload_invalid"
    end
  end

  defp base64url_32?(value) do
    with true <- Regex.match?(@base64url_re, value),
         false <- rem(byte_size(value), 4) == 1,
         {:ok, bytes} <- Base.url_decode64(value, padding: false) do
      byte_size(bytes) == 32 and Base.url_encode64(bytes, padding: false) == value
    else
      _ -> false
    end
  end

  defp assert_signature_envelopes!(signatures) do
    if signatures == [] do
      raise ArgumentError, "workspace_pin_signature_missing"
    end

    Enum.each(signatures, fn
      %{} = signature_envelope ->
        assert_exact_keys!(
          signature_envelope,
          @signature_envelope_keys,
          "workspace_pin_signature_invalid"
        )

      _ ->
        raise ArgumentError, "workspace_pin_signature_invalid"
    end)
  end

  defp assert_exact_keys!(map, keys, error) when is_map(map) do
    if Enum.sort(Map.keys(map)) == keys do
      :ok
    else
      raise ArgumentError, error
    end
  end
end
