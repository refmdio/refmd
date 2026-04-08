defmodule RefMDWeb.DocumentEnvelope do
  @moduledoc false

  alias RefMD.Documents

  @update_public_data_keys ~w(docId deviceId signingPubKey clock keyVersion timestamp refSnapshotId updateHash)
  @snapshot_public_data_keys ~w(docId deviceId signingPubKey snapshotId keyVersion parentSnapshotId parentSnapshotProof parentSnapshotUpdateClocks)
  @ephemeral_public_data_keys ~w(docId deviceId signingPubKey)

  # ── Envelope Parsing ──────────────────────────

  @spec parse_update_envelope(map(), Phoenix.Socket.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_update_envelope(payload, socket) do
    public_data = payload["publicData"]

    with {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @update_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_pub_key(public_data, socket),
         :ok <- validate_device_id(public_data, socket),
         :ok <- validate_integer_field(public_data, "clock"),
         :ok <- validate_integer_field(public_data, "keyVersion"),
         :ok <- validate_integer_field(public_data, "timestamp"),
         :ok <- validate_uuid_field(public_data, "refSnapshotId"),
         :ok <- validate_string_field(public_data, "updateHash"),
         {:ok, ciphertext_raw} <- decode_field(payload, "ciphertext"),
         {:ok, nonce_raw} <- decode_and_validate_nonce(payload),
         {:ok, signature_raw} <- decode_field(payload, "signature") do
      {:ok,
       %{
         ciphertext_raw: ciphertext_raw,
         nonce_raw: nonce_raw,
         signature_raw: signature_raw,
         public_data: public_data
       }}
    end
  end

  @spec parse_snapshot_envelope(map(), Phoenix.Socket.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_snapshot_envelope(payload, socket) do
    public_data = payload["publicData"]

    with {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @snapshot_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_pub_key(public_data, socket),
         :ok <- validate_device_id(public_data, socket),
         :ok <- validate_uuid_field(public_data, "snapshotId"),
         :ok <- validate_integer_field(public_data, "keyVersion"),
         :ok <- validate_snapshot_lineage(public_data),
         {:ok, ciphertext_raw} <- decode_field(payload, "ciphertext"),
         {:ok, nonce_raw} <- decode_and_validate_nonce(payload),
         {:ok, signature_raw} <- decode_field(payload, "signature") do
      {:ok,
       %{
         ciphertext_raw: ciphertext_raw,
         nonce_raw: nonce_raw,
         signature_raw: signature_raw,
         public_data: public_data
       }}
    end
  end

  @spec parse_ephemeral_envelope(map(), Phoenix.Socket.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_ephemeral_envelope(payload, socket) do
    public_data = payload["publicData"]

    with {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @ephemeral_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_pub_key(public_data, socket),
         :ok <- validate_device_id(public_data, socket),
         {:ok, _ciphertext_raw} <- decode_field(payload, "ciphertext"),
         {:ok, _nonce_raw} <- decode_and_validate_nonce(payload),
         {:ok, signature_raw} <- decode_field(payload, "signature") do
      {:ok,
       %{
         signature_raw: signature_raw,
         public_data: public_data
       }}
    end
  end

  # ── Signature Verification ────────────────────

  @spec verify_envelope_signature(String.t(), map(), map(), Phoenix.Socket.t()) ::
          :ok | {:error, String.t()}
  def verify_envelope_signature(prefix, payload, parsed, socket) do
    verified =
      try do
        RefMD.Crypto.verify_ws_envelope_signature(
          prefix,
          payload["ciphertext"],
          payload["nonce"],
          parsed.public_data,
          parsed.signature_raw,
          socket.assigns.device_signing_pub_key_raw
        )
      rescue
        _ -> false
      end

    if verified, do: :ok, else: {:error, "signature_verification_failed"}
  end

  @spec verify_update_hash(map(), Phoenix.Socket.t()) :: :ok | {:error, String.t()}
  def verify_update_hash(parsed, socket) do
    claimed_hash = parsed.public_data["updateHash"]

    params = %{
      "clock" => parsed.public_data["clock"],
      "device_signing_pub_key" => socket.assigns.device_signing_pub_key,
      "document_id" => socket.assigns.document_id,
      "encrypted_content" => Base.url_encode64(parsed.ciphertext_raw, padding: false),
      "key_version" => parsed.public_data["keyVersion"],
      "nonce" => Base.url_encode64(parsed.nonce_raw, padding: false),
      "ref_snapshot_id" => parsed.public_data["refSnapshotId"],
      "timestamp" => parsed.public_data["timestamp"]
    }

    if RefMD.Crypto.verify_update_hash(claimed_hash, params) do
      :ok
    else
      {:error, "update_hash_mismatch"}
    end
  end

  # ── Formatters ────────────────────────────────

  @spec format_snapshot(nil | RefMD.Documents.DocumentSnapshot.t()) :: nil | map()
  def format_snapshot(nil), do: nil

  def format_snapshot(snap) do
    %{
      ciphertext: Base.url_encode64(snap.data, padding: false),
      nonce: Base.url_encode64(snap.nonce, padding: false),
      signature: Base.url_encode64(snap.signature, padding: false),
      publicData: %{
        docId: snap.document_id,
        snapshotId: snap.id,
        deviceId: snap.device_id,
        signingPubKey: snap.created_by_device,
        keyVersion: snap.key_version,
        parentSnapshotId: snap.parent_snapshot_id,
        parentSnapshotProof: snap.parent_snapshot_proof,
        parentSnapshotUpdateClocks: snap.parent_snapshot_update_clocks
      }
    }
  end

  @spec format_update(RefMD.Documents.DocumentUpdate.t()) :: map()
  def format_update(update) do
    base = %{
      ciphertext: Base.url_encode64(update.update_data, padding: false),
      nonce: Base.url_encode64(update.nonce, padding: false),
      version: update.version,
      publicData: %{
        docId: update.document_id,
        deviceId: update.device_id,
        signingPubKey: update.device_signing_pub_key,
        keyVersion: update.key_version,
        refSnapshotId: update.snapshot_id,
        clock: update.clock,
        timestamp: update.timestamp,
        updateHash: update.update_hash
      }
    }

    if update.signature do
      Map.put(base, :signature, Base.url_encode64(update.signature, padding: false))
    else
      Map.put(base, :mac, Base.url_encode64(update.mac, padding: false))
    end
  end

  @spec build_snapshot_failure(map() | nil, Ecto.UUID.t(), Ecto.UUID.t() | nil) :: map()
  def build_snapshot_failure(nil, _document_id, _known_snapshot_id) do
    %{snapshot: nil, updates: [], snapshotProofChain: []}
  end

  def build_snapshot_failure(
        %{snapshot: snapshot, updates: updates},
        document_id,
        known_snapshot_id
      ) do
    active_snapshot_id = if snapshot, do: snapshot.id

    proof_chain =
      Documents.build_snapshot_proof_chain(document_id, known_snapshot_id, active_snapshot_id)

    %{
      snapshot: format_snapshot(snapshot),
      updates: Enum.map(updates, &format_update/1),
      snapshotProofChain: proof_chain
    }
  end

  # ── Validation Helpers (private) ──────────────

  defp validate_map(nil, name), do: {:error, "missing_#{name}"}
  defp validate_map(m, _name) when is_map(m), do: {:ok, m}
  defp validate_map(_, name), do: {:error, "invalid_#{name}"}

  defp validate_exact_keys(public_data, allowed_keys) do
    extra = Map.keys(public_data) -- allowed_keys

    if extra == [] do
      :ok
    else
      {:error, "unexpected_publicData_keys"}
    end
  end

  defp validate_doc_id(public_data, socket) do
    if public_data["docId"] == socket.assigns.document_id do
      :ok
    else
      {:error, "doc_id_mismatch"}
    end
  end

  defp validate_signing_pub_key(public_data, socket) do
    if public_data["signingPubKey"] == socket.assigns.device_signing_pub_key do
      :ok
    else
      {:error, "signing_pub_key_mismatch"}
    end
  end

  defp validate_device_id(public_data, socket) do
    if public_data["deviceId"] == socket.assigns.device_id do
      :ok
    else
      {:error, "device_id_mismatch"}
    end
  end

  defp validate_snapshot_lineage(public_data) do
    with :ok <- validate_nullable_uuid_field(public_data, "parentSnapshotId"),
         :ok <- validate_parent_snapshot_proof(public_data["parentSnapshotProof"]) do
      validate_parent_snapshot_clocks(public_data["parentSnapshotUpdateClocks"])
    end
  end

  defp validate_nullable_uuid_field(public_data, field) do
    if Map.has_key?(public_data, field) do
      validate_nullable_uuid_value(public_data[field], field)
    else
      {:error, "missing_#{field}"}
    end
  end

  defp validate_nullable_uuid_value(nil, _field), do: :ok

  defp validate_nullable_uuid_value(v, field) when is_binary(v) do
    case Ecto.UUID.cast(v) do
      {:ok, _} -> :ok
      :error -> {:error, "invalid_#{field}"}
    end
  end

  defp validate_nullable_uuid_value(_, field), do: {:error, "invalid_#{field}"}

  defp validate_parent_snapshot_proof(proof) when is_binary(proof), do: :ok
  defp validate_parent_snapshot_proof(_), do: {:error, "invalid_parentSnapshotProof"}

  defp validate_parent_snapshot_clocks(clocks) when is_map(clocks) do
    if Enum.all?(clocks, fn {_k, v} -> is_integer(v) end) do
      :ok
    else
      {:error, "invalid_parentSnapshotUpdateClocks"}
    end
  end

  defp validate_parent_snapshot_clocks(_), do: {:error, "invalid_parentSnapshotUpdateClocks"}

  defp validate_string_field(public_data, field) do
    case public_data[field] do
      v when is_binary(v) -> :ok
      nil -> {:error, "missing_#{field}"}
      _ -> {:error, "invalid_#{field}"}
    end
  end

  defp validate_uuid_field(public_data, field) do
    case public_data[field] do
      nil ->
        {:error, "missing_#{field}"}

      v when is_binary(v) ->
        case Ecto.UUID.cast(v) do
          {:ok, _} -> :ok
          :error -> {:error, "invalid_#{field}"}
        end

      _ ->
        {:error, "invalid_#{field}"}
    end
  end

  defp validate_integer_field(public_data, field) do
    case public_data[field] do
      v when is_integer(v) -> :ok
      nil -> {:error, "missing_#{field}"}
      _ -> {:error, "invalid_#{field}"}
    end
  end

  defp decode_and_validate_nonce(params) do
    with {:ok, nonce} <- decode_field(params, "nonce") do
      if byte_size(nonce) == 24 do
        {:ok, nonce}
      else
        {:error, "invalid_nonce_length"}
      end
    end
  end

  defp decode_field(params, key) do
    case params[key] do
      nil ->
        {:error, "missing_#{key}"}

      val ->
        case Base.url_decode64(val, padding: false) do
          {:ok, decoded} -> {:ok, decoded}
          :error -> {:error, "invalid_#{key}"}
        end
    end
  end
end
