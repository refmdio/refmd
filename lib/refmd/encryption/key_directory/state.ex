defmodule RefMD.Encryption.KeyDirectory.State do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Encryption.KeyDirectory.{Assertions, Protocol, SignatureEnvelope}

  def assert_checkpoint_state_matches_replay!(candidate_payload, replay_payload) do
    for key <- ["identity_keys", "device_keys", "share_participant_keys", "revoked_key_ids"] do
      if normalize_checkpoint_state_entries!(candidate_payload[key]) !=
           normalize_checkpoint_state_entries!(replay_payload[key]) do
        raise ArgumentError, "checkpoint_state_replay_mismatch"
      end
    end

    :ok
  end

  def normalize_checkpoint_state_entries!(entries) when is_list(entries) do
    entries
    |> Enum.map(fn
      %{"key_id" => key_id} = entry when is_binary(key_id) ->
        {key_id, JCS.canonical_bytes!(entry)}

      key_id when is_binary(key_id) ->
        {key_id, key_id}

      _entry ->
        raise ArgumentError, "checkpoint_state_entry_invalid"
    end)
    |> Enum.sort()
    |> tap(fn keyed ->
      key_count = keyed |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> length()
      if key_count != length(keyed), do: raise(ArgumentError, "checkpoint_state_entry_duplicate")
    end)
  end

  def normalize_checkpoint_state_entries!(_),
    do: raise(ArgumentError, "checkpoint_state_entry_invalid")

  def update_key_entries!(checkpoint_payload, key, key_entry) do
    entries = Map.fetch!(checkpoint_payload, key)

    if Enum.any?(entries, &(&1["key_id"] == key_entry["key_id"])) do
      raise ArgumentError, "key_directory_key_entry_duplicate"
    end

    Map.put(checkpoint_payload, key, entries ++ [key_entry])
  end

  def update_key_entries_if_missing!(checkpoint_payload, key, key_entry) do
    entries = Map.fetch!(checkpoint_payload, key)

    if Enum.any?(entries, &(&1["key_id"] == key_entry["key_id"])) do
      checkpoint_payload
    else
      Map.put(checkpoint_payload, key, entries ++ [key_entry])
    end
  end

  def revoke_key_entry!(checkpoint_payload, key_id, payload) do
    event_ref = event_ref!(payload)

    found? =
      Enum.any?(key_directory_authority_entries(checkpoint_payload), fn entry ->
        entry["key_id"] == key_id
      end)

    unless found?, do: raise(ArgumentError, "key_directory_key_entry_missing")

    checkpoint_payload
    |> Map.update!("identity_keys", &revoke_key_entry_in_list!(&1, key_id, event_ref))
    |> Map.update!("device_keys", &revoke_key_entry_in_list!(&1, key_id, event_ref))
    |> Map.update!("revoked_key_ids", fn revoked -> Enum.uniq(revoked ++ [key_id]) end)
  end

  def revoke_key_entry_in_list!(entries, key_id, event_ref) do
    Enum.map(entries, fn entry ->
      revoke_matching_key_entry!(entry, key_id, event_ref)
    end)
  end

  def revoke_matching_key_entry!(%{"key_id" => key_id, "revoked_at" => _}, key_id, _event_ref),
    do: raise(ArgumentError, "key_directory_key_already_revoked")

  def revoke_matching_key_entry!(%{"key_id" => key_id} = entry, key_id, event_ref),
    do: Map.put(entry, "revoked_at", event_ref)

  def revoke_matching_key_entry!(entry, _key_id, _event_ref), do: entry

  def assert_key_entry_valid_from_event!(key_entry, payload) do
    Assertions.assert_literal!(
      key_entry["valid_from"],
      event_ref!(payload),
      "key_entry_valid_from_mismatch"
    )
  end

  def assert_key_material_hash!(key_entry, expected_hash, error) do
    actual_hash = Hash.blake3_base64url(JCS.canonical_bytes!(key_entry["key_material"]))
    Assertions.assert_literal!(expected_hash, actual_hash, error)
  end

  def event_ref!(payload) do
    %{
      "scope_kind" => payload["scope_kind"],
      "scope_id" => payload["scope_id"],
      "event_sequence" => payload["sequence"],
      "event_hash" => Protocol.event_hash(payload)
    }
  end

  def key_entry_by_id!(checkpoint_payload, key_id) do
    key_directory_authority_entries(checkpoint_payload)
    |> Enum.find(fn
      %{"key_id" => ^key_id} -> true
      _ -> false
    end)
    |> case do
      nil -> raise(ArgumentError, "key_directory_key_entry_missing")
      entry -> entry
    end
  end

  def find_key_entry_by_id(checkpoint_payload, key_id) do
    key_directory_authority_entries(checkpoint_payload)
    |> Enum.find(fn
      %{"key_id" => ^key_id} -> true
      _ -> false
    end)
  end

  def assert_key_entry_active_at_sequence!(checkpoint_payload, key_id, sequence) do
    entry = key_entry_by_id!(checkpoint_payload, key_id)
    valid_from = entry["valid_from"]["event_sequence"]

    if valid_from > sequence do
      raise ArgumentError, "key_directory_signer_not_yet_valid"
    end

    if Map.has_key?(entry, "revoked_at") and entry["revoked_at"]["event_sequence"] <= sequence do
      raise ArgumentError, "key_directory_signer_revoked"
    end

    :ok
  end

  def share_participant_signer(signatures) do
    Enum.find_value(signatures, fn signature_envelope ->
      {signer, _signature} = SignatureEnvelope.parts!(signature_envelope)
      if signer["signer_kind"] == "share_participant_device", do: signer, else: nil
    end)
  end

  def invitation_redeem_authority_signer(signatures) do
    Enum.find_value(signatures, fn signature_envelope ->
      {signer, _signature} = SignatureEnvelope.parts!(signature_envelope)
      if signer["signer_kind"] == "invitation_redeem_authority", do: signer, else: nil
    end)
  end

  def assert_invitation_redeem_authority_matches!(signatures, body, invitation_id_field) do
    signer = invitation_redeem_authority_signer(signatures)
    if is_nil(signer), do: raise(ArgumentError, "invitation_redeem_authority_signer_missing")

    Assertions.assert_literal!(
      signer["invitation_id"],
      body[invitation_id_field],
      "invitation_redeem_authority_invitation_id_mismatch"
    )
  end

  def key_directory_authority_entries(checkpoint_payload) do
    checkpoint_payload["identity_keys"] ++
      checkpoint_payload["device_keys"] ++
      checkpoint_payload["share_participant_keys"] ++
      Map.get(checkpoint_payload, "temporary_authority_keys", [])
  end

  def share_participant_key_entry_by_id!(checkpoint_payload, key_id) do
    checkpoint_payload["share_participant_keys"]
    |> Enum.find(fn
      %{"key_id" => ^key_id} -> true
      _ -> false
    end)
    |> case do
      nil -> raise(ArgumentError, "share_participant_key_entry_missing")
      entry -> entry
    end
  end

  def share_participant_entries_by_id(checkpoint_payload) do
    checkpoint_payload["share_participant_keys"]
    |> Enum.map(fn
      %{"key_id" => key_id} = entry when is_binary(key_id) -> {key_id, entry}
      _ -> nil
    end)
    |> Enum.reject(&is_nil/1)
    |> Map.new()
  end

  def authorized_share_participant_key_entry!(authorized_share_participant_keys, key_id)
      when is_map(authorized_share_participant_keys) and is_binary(key_id) do
    case Map.get(authorized_share_participant_keys, key_id) do
      %{} = entry -> entry
      _ -> raise(ArgumentError, "share_participant_key_entry_unauthorized")
    end
  end
end
