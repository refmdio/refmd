defmodule RefMDWeb.Channels.Document.Envelope do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Documents
  alias RefMD.Encryption

  @key_checkpoint_public_data_keys ~w(keyCheckpointSequence keyCheckpointHash)
  @authority_public_data_keys ~w(ownerKind ownerId authorityKind authorityId authorityContextKey authorityScopeId authorityPermissionVersion)
  @update_public_data_keys ~w(docId signingKeyId clock keyVersion timestamp refSnapshotId updateHash) ++
                             ~w(minDekVersion writeSessionEventHash writeSessionId writeSessionCounter) ++
                             @authority_public_data_keys ++
                             @key_checkpoint_public_data_keys
  @write_session_public_data_keys ~w(docId signingKeyId keyVersion) ++
                                    ~w(minDekVersion writeSessionEventHash writeSessionId writeSessionCounter) ++
                                    @authority_public_data_keys ++
                                    @key_checkpoint_public_data_keys
  @snapshot_public_data_keys ~w(docId signingKeyId snapshotId keyVersion parentSnapshotId parentProofHash parentSnapshotUpdateClocks) ++
                               @authority_public_data_keys ++
                               @key_checkpoint_public_data_keys
  @workspace_event_head_public_data_keys ~w(workspaceEventHeadSequence workspaceEventHeadHash)
  @ephemeral_public_data_keys ~w(docId signingKeyId) ++
                                @authority_public_data_keys ++
                                @key_checkpoint_public_data_keys ++
                                @workspace_event_head_public_data_keys
  @signed_document_envelope_keys ~w(admission ciphertext nonce publicData signature)
  @write_session_envelope_keys ~w(admission publicData)
  @ephemeral_envelope_keys ~w(ciphertext nonce publicData signature)

  # ── Envelope Parsing ──────────────────────────

  @spec parse_update_envelope(map(), Phoenix.Socket.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_update_envelope(payload, socket) do
    public_data = payload["publicData"]

    with {:ok, admission} <- validate_admission_artifacts(payload),
         :ok <-
           validate_exact_keys(
             payload,
             @signed_document_envelope_keys,
             "unexpected_envelope_keys"
           ),
         {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @update_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_key_id(public_data, socket),
         :ok <- validate_authority_fields(public_data, socket),
         :ok <- validate_integer_field(public_data, "clock"),
         :ok <- validate_integer_field(public_data, "keyVersion"),
         :ok <- validate_integer_field(public_data, "timestamp"),
         :ok <- validate_integer_field(public_data, "minDekVersion"),
         :ok <- validate_hash_field(public_data, "writeSessionEventHash"),
         :ok <- validate_string_field(public_data, "writeSessionId"),
         :ok <- validate_integer_field(public_data, "writeSessionCounter"),
         :ok <- validate_key_checkpoint_fields(public_data),
         :ok <- validate_uuid_field(public_data, "refSnapshotId"),
         :ok <- validate_string_field(public_data, "updateHash"),
         {:ok, ciphertext_raw} <- decode_field(payload, "ciphertext"),
         {:ok, nonce_raw} <- decode_and_validate_nonce(payload),
         {:ok, signature} <- validate_signature_object(payload["signature"]),
         :ok <- validate_key_checkpoint_boundary(public_data, admission) do
      {:ok,
       %{
         ciphertext_raw: ciphertext_raw,
         nonce_raw: nonce_raw,
         signature: signature,
         admission: admission,
         public_data: public_data
       }}
    end
  end

  @spec parse_write_session_envelope(map(), Phoenix.Socket.t()) ::
          {:ok, map()} | {:error, String.t()}
  def parse_write_session_envelope(payload, socket) do
    public_data = payload["publicData"]

    with {:ok, admission} <- validate_admission_artifacts(payload),
         :ok <-
           validate_exact_keys(payload, @write_session_envelope_keys, "unexpected_envelope_keys"),
         {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @write_session_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_key_id(public_data, socket),
         :ok <- validate_authority_fields(public_data, socket),
         :ok <- validate_integer_field(public_data, "keyVersion"),
         :ok <- validate_integer_field(public_data, "minDekVersion"),
         :ok <- validate_hash_field(public_data, "writeSessionEventHash"),
         :ok <- validate_string_field(public_data, "writeSessionId"),
         :ok <- validate_integer_field(public_data, "writeSessionCounter"),
         :ok <- validate_key_checkpoint_fields(public_data),
         :ok <- validate_key_checkpoint_boundary(public_data, admission) do
      {:ok, %{admission: admission, public_data: public_data}}
    end
  end

  @spec parse_snapshot_envelope(map(), Phoenix.Socket.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_snapshot_envelope(payload, socket) do
    public_data = payload["publicData"]

    with {:ok, admission} <- validate_admission_artifacts(payload),
         :ok <-
           validate_exact_keys(
             payload,
             @signed_document_envelope_keys,
             "unexpected_envelope_keys"
           ),
         {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @snapshot_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_key_id(public_data, socket),
         :ok <- validate_authority_fields(public_data, socket),
         :ok <- validate_uuid_field(public_data, "snapshotId"),
         :ok <- validate_integer_field(public_data, "keyVersion"),
         :ok <- validate_key_checkpoint_fields(public_data),
         :ok <- validate_snapshot_lineage(public_data),
         {:ok, ciphertext_raw} <- decode_field(payload, "ciphertext"),
         {:ok, nonce_raw} <- decode_and_validate_nonce(payload),
         {:ok, signature} <- validate_signature_object(payload["signature"]),
         :ok <- validate_key_checkpoint_boundary(public_data, admission) do
      {:ok,
       %{
         ciphertext_raw: ciphertext_raw,
         nonce_raw: nonce_raw,
         signature: signature,
         admission: admission,
         public_data: public_data
       }}
    end
  end

  @spec parse_ephemeral_envelope(map(), Phoenix.Socket.t()) :: {:ok, map()} | {:error, String.t()}
  def parse_ephemeral_envelope(payload, socket) do
    public_data = payload["publicData"]

    with :ok <- validate_exact_keys(payload, @ephemeral_envelope_keys, "unexpected_envelope_keys"),
         {:ok, _} <- validate_map(public_data, "publicData"),
         :ok <- validate_exact_keys(public_data, @ephemeral_public_data_keys),
         :ok <- validate_doc_id(public_data, socket),
         :ok <- validate_signing_key_id(public_data, socket),
         :ok <- validate_authority_fields(public_data, socket),
         :ok <- validate_key_checkpoint_fields(public_data),
         :ok <- validate_workspace_event_head_fields(public_data),
         {:ok, _ciphertext_raw} <- decode_field(payload, "ciphertext"),
         {:ok, _nonce_raw} <- decode_and_validate_nonce(payload),
         {:ok, signature} <- validate_signature_object(payload["signature"]) do
      {:ok,
       %{
         signature: signature,
         public_data: public_data
       }}
    end
  end

  # ── Signature Verification ────────────────────

  @spec verify_envelope_signature(String.t(), map(), map(), Phoenix.Socket.t()) ::
          :ok | {:error, String.t()}
  def verify_envelope_signature("refmd_update", payload, parsed, socket) do
    with {:ok, public_material} <- get_socket_public_material(socket),
         signing_key_id when is_binary(signing_key_id) <- socket.assigns[:device_signing_key_id],
         transcript <-
           Signature.build_document_update_transcript!(%{
             owner_kind: collaboration_owner_kind(socket),
             owner_id: socket.assigns.device_id,
             workspace_id: socket.assigns.document.workspace_id,
             actor_user_id: socket.assigns.current_user_id,
             actor_device_id: socket.assigns.device_id,
             signing_key_id: signing_key_id,
             public_data: parsed.public_data,
             authority_boundary:
               write_session_authority_boundary(
                 socket.assigns.document.workspace_id,
                 parsed
               ),
             ciphertext: payload["ciphertext"],
             nonce: payload["nonce"]
           }),
         :ok <-
           Signature.verify_hybrid_signature_result(
             "document_update",
             transcript,
             parsed.signature,
             public_material,
             semantic_context(socket, signing_key_id)
           ) do
      :ok
    else
      {:error, :invalid_signature} -> {:error, "invalid_signature"}
      {:error, reason} -> {:error, signature_semantic_error(reason)}
      _ -> {:error, "invalid_signature"}
    end
  rescue
    ArgumentError -> {:error, "invalid_signature"}
  end

  def verify_envelope_signature("refmd_snapshot", payload, parsed, socket) do
    with {:ok, public_material} <- get_socket_public_material(socket),
         signing_key_id when is_binary(signing_key_id) <- socket.assigns[:device_signing_key_id],
         transcript <-
           Signature.build_document_snapshot_transcript!(%{
             owner_kind: collaboration_owner_kind(socket),
             owner_id: socket.assigns.device_id,
             workspace_id: socket.assigns.document.workspace_id,
             actor_user_id: socket.assigns.current_user_id,
             actor_device_id: socket.assigns.device_id,
             signing_key_id: signing_key_id,
             public_data: parsed.public_data,
             authority_boundary: authority_boundary(parsed, "document_snapshot_accepted"),
             ciphertext: payload["ciphertext"],
             nonce: payload["nonce"]
           }),
         :ok <-
           Signature.verify_hybrid_signature_result(
             "document_snapshot",
             transcript,
             parsed.signature,
             public_material,
             semantic_context(socket, signing_key_id)
           ) do
      :ok
    else
      {:error, :invalid_signature} -> {:error, "invalid_signature"}
      {:error, reason} -> {:error, signature_semantic_error(reason)}
      _ -> {:error, "invalid_signature"}
    end
  rescue
    ArgumentError -> {:error, "invalid_signature"}
  end

  def verify_envelope_signature("refmd_ephemeral", payload, parsed, socket) do
    with {:ok, public_material} <- get_socket_public_material(socket),
         signing_key_id when is_binary(signing_key_id) <- socket.assigns[:device_signing_key_id],
         transcript <-
           Signature.build_editor_ephemeral_transcript!(%{
             owner_kind: collaboration_owner_kind(socket),
             owner_id: socket.assigns.device_id,
             actor_user_id: socket.assigns.current_user_id,
             actor_device_id: socket.assigns.device_id,
             signing_key_id: signing_key_id,
             workspace_id: socket.assigns.document.workspace_id,
             public_data: parsed.public_data,
             authority_boundary:
               ephemeral_authority_boundary(
                 socket.assigns.document.workspace_id,
                 parsed.public_data
               ),
             ciphertext: payload["ciphertext"],
             nonce: payload["nonce"]
           }),
         :ok <-
           Signature.verify_hybrid_signature_result(
             "editor_ephemeral",
             transcript,
             parsed.signature,
             public_material,
             semantic_context(socket, signing_key_id, :ephemeral)
           ) do
      :ok
    else
      {:error, :invalid_signature} -> {:error, "invalid_signature"}
      {:error, reason} -> {:error, signature_semantic_error(reason)}
      _ -> {:error, "invalid_signature"}
    end
  rescue
    ArgumentError -> {:error, "invalid_signature"}
  end

  def verify_envelope_signature(_prefix, _payload, _parsed, _socket),
    do: {:error, "invalid_signature"}

  defp signature_semantic_error(reason) when is_atom(reason), do: Atom.to_string(reason)

  defp semantic_context(socket, signing_key_id) do
    %{
      document: socket.assigns.document,
      session: %{
        kind: socket.assigns[:session_kind],
        user_id: socket.assigns[:current_user_id],
        device_id: socket.assigns[:device_id],
        principal_id: socket.assigns[:share_participant_principal_id],
        signing_key_id: signing_key_id
      }
    }
  end

  defp semantic_context(socket, signing_key_id, :ephemeral) do
    socket
    |> semantic_context(signing_key_id)
    |> Map.put(
      :workspace_event_head,
      current_workspace_event_head!(socket.assigns.document.workspace_id)
    )
  end

  defp current_workspace_event_head!(workspace_id) do
    case Encryption.current_workspace_key_directory_pin(workspace_id) do
      %{event_head_sequence: sequence, event_head_hash: hash}
      when is_integer(sequence) and is_binary(hash) ->
        %{sequence: sequence, hash: hash}

      _ ->
        raise ArgumentError, "ephemeral_workspace_head_context_missing"
    end
  end

  defp validate_signature_object(signature) when is_map(signature) do
    JCS.canonical_bytes!(signature)
    {:ok, signature}
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp validate_signature_object(_signature), do: {:error, :invalid_signature}

  defp get_socket_public_material(%{
         assigns: %{device_hybrid_signing_public_key_material: material}
       })
       when is_map(material),
       do: {:ok, material}

  defp get_socket_public_material(_socket), do: {:error, :missing_public_key_material}

  defp collaboration_owner_kind(socket) do
    if socket.assigns[:session_kind] == :share_participant,
      do: "share_participant_device",
      else: "device"
  end

  defp share_authority_principal_id(%{assigns: %{session_kind: :share_participant}} = socket),
    do: socket.assigns.share_participant_principal_id

  @spec verify_update_hash(map(), Phoenix.Socket.t()) :: :ok | {:error, String.t()}
  def verify_update_hash(parsed, socket) do
    claimed_hash = parsed.public_data["updateHash"]

    params = %{
      "clock" => parsed.public_data["clock"],
      "signing_key_id" => socket.assigns.device_signing_key_id,
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

  @spec format_snapshot(nil | RefMD.Documents.DocumentSnapshot.t(), keyword()) :: nil | map()
  def format_snapshot(snap, opts \\ [])
  def format_snapshot(nil, _opts), do: nil

  def format_snapshot(snap, opts) do
    %{
      ciphertext: Base.url_encode64(snap.data, padding: false),
      nonce: Base.url_encode64(snap.nonce, padding: false),
      signature: snap.hybrid_signature,
      admission:
        format_admission!(
          snap.document_id,
          "document_snapshot_accepted",
          snap.snapshot_admission_event_hash,
          opts
        ),
      publicData: %{
        docId: snap.document_id,
        snapshotId: snap.id,
        signingKeyId: snap.created_by_signing_key_id,
        keyVersion: snap.key_version,
        parentSnapshotId: snap.parent_snapshot_id || "GENESIS",
        parentProofHash: snap.parent_proof_hash,
        parentSnapshotUpdateClocks: snap.parent_snapshot_update_clocks,
        ownerKind: snap.owner_kind,
        ownerId: snap.owner_id,
        authorityKind: snap.authority_kind,
        authorityId: snap.authority_id,
        authorityContextKey: snap.authority_context_key,
        authorityScopeId: snap.authority_scope_id,
        authorityPermissionVersion: snap.authority_permission_version,
        keyCheckpointSequence: snap.key_checkpoint_sequence,
        keyCheckpointHash: snap.key_checkpoint_hash
      }
    }
  end

  @spec format_incremental_snapshot(RefMD.Documents.DocumentSnapshot.t()) :: map()
  def format_incremental_snapshot(snap), do: format_snapshot(snap, incremental: true)

  @spec format_update(RefMD.Documents.DocumentUpdate.t()) :: map()
  def format_update(update), do: format_update(update, :full)

  @spec format_compact_update(RefMD.Documents.DocumentUpdate.t()) :: map()
  def format_compact_update(update), do: format_update(update, :compact)

  @spec format_incremental_update(RefMD.Documents.DocumentUpdate.t()) :: map()
  def format_incremental_update(update), do: format_update(update, :incremental)

  @spec format_initial_updates([RefMD.Documents.DocumentUpdate.t()], boolean()) :: [map()]
  def format_initial_updates(updates, admission_seeded?) do
    {formatted, _cache, _seeded?} =
      Enum.reduce(updates, {[], %{}, admission_seeded?}, fn update, {acc, cache, seeded?} ->
        mode = if seeded?, do: :incremental, else: :full
        {formatted_update, cache} = format_update_cached(update, mode, cache)
        {[formatted_update | acc], cache, true}
      end)

    Enum.reverse(formatted)
  end

  defp format_update_cached(update, mode, cache) do
    signature = update.hybrid_signature || raise ArgumentError, "hybrid_signature_required"
    cache_key = {mode, update.admission_event_hash}

    {admission, cache} =
      case Map.fetch(cache, cache_key) do
        {:ok, cached} ->
          {cached, cache}

        :error ->
          {admission, cache} = cached_update_admission(update, mode, cache)
          {admission, Map.put(cache, cache_key, admission)}
      end

    {format_update_with_admission(update, signature, admission), cache}
  end

  defp cached_update_admission(update, :incremental, cache) do
    admission =
      format_admission!(
        update.document_id,
        "document_write_session_admitted",
        update.admission_event_hash,
        incremental: true
      )

    {admission, Map.put(cache, {:incremental, update.admission_event_hash}, admission)}
  end

  defp cached_update_admission(update, :full, cache) do
    admission =
      format_admission!(
        update.document_id,
        "document_write_session_admitted",
        update.admission_event_hash
      )

    {admission, Map.put(cache, {:full, update.admission_event_hash}, admission)}
  end

  defp format_update(update, mode) when mode in [:full, :compact, :incremental] do
    signature = update.hybrid_signature || raise ArgumentError, "hybrid_signature_required"

    admission_opts =
      case mode do
        :compact -> [compact: true]
        :incremental -> [incremental: true]
        :full -> []
      end

    admission =
      format_admission!(
        update.document_id,
        "document_write_session_admitted",
        update.admission_event_hash,
        admission_opts
      )

    format_update_with_admission(update, signature, admission)
  end

  defp format_update_with_admission(update, signature, admission) do
    body = admission_event_body!(admission, "document_write_session_admitted")

    base = %{
      ciphertext: Base.url_encode64(update.update_data, padding: false),
      nonce: Base.url_encode64(update.nonce, padding: false),
      version: update.version,
      publicData: %{
        docId: update.document_id,
        signingKeyId: update.signing_key_id,
        keyVersion: update.key_version,
        refSnapshotId: update.snapshot_id,
        clock: update.clock,
        timestamp: update.timestamp,
        updateHash: update.update_hash,
        ownerKind: update.owner_kind,
        ownerId: update.owner_id,
        authorityKind: update.authority_kind,
        authorityId: update.authority_id,
        authorityContextKey: update.authority_context_key,
        authorityScopeId: update.authority_scope_id,
        authorityPermissionVersion: update.authority_permission_version,
        keyCheckpointSequence: update.key_checkpoint_sequence,
        keyCheckpointHash: update.key_checkpoint_hash,
        minDekVersion: body["min_dek_version"],
        writeSessionEventHash: update.admission_event_hash,
        writeSessionId: body["session_id"],
        writeSessionCounter: update.write_session_counter
      }
    }

    base
    |> Map.put(:signature, signature)
    |> Map.put(:admission, admission)
  end

  defp format_admission!(document_id, event_type, admission_event_hash, opts \\ []) do
    Documents.document_admission_package!(document_id, event_type, admission_event_hash, opts)
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
      updates: format_initial_updates(updates, !is_nil(snapshot)),
      snapshotProofChain: proof_chain,
      proofChainHash: if(snapshot, do: snapshot.proof_chain_hash),
      ciphertextHash: if(snapshot, do: snapshot.ciphertext_hash),
      snapshotAdmissionEventHash: if(snapshot, do: snapshot.snapshot_admission_event_hash)
    }
  end

  # ── Validation Helpers (private) ──────────────

  defp validate_map(nil, name), do: {:error, "missing_#{name}"}
  defp validate_map(m, _name) when is_map(m), do: {:ok, m}
  defp validate_map(_, name), do: {:error, "invalid_#{name}"}

  defp validate_exact_keys(public_data, allowed_keys) do
    validate_exact_keys(public_data, allowed_keys, "unexpected_publicData_keys")
  end

  defp validate_exact_keys(public_data, allowed_keys, error) do
    if Enum.sort(Map.keys(public_data)) == Enum.sort(allowed_keys) do
      :ok
    else
      {:error, error}
    end
  end

  defp validate_doc_id(public_data, socket) do
    if public_data["docId"] == socket.assigns.document_id do
      :ok
    else
      {:error, "doc_id_mismatch"}
    end
  end

  defp validate_signing_key_id(public_data, socket) do
    if public_data["signingKeyId"] == socket.assigns.device_signing_key_id do
      :ok
    else
      {:error, "signing_key_id_mismatch"}
    end
  end

  defp validate_authority_fields(public_data, socket) do
    expected_authority_fields(socket, public_data)
    |> Enum.find_value(:ok, &authority_field_error(public_data, &1))
  end

  defp authority_field_error(public_data, {field, expected, error}) do
    if public_data[field] == expected, do: false, else: {:error, error}
  end

  defp expected_authority_fields(socket, public_data) do
    context = authority_context(socket)

    [
      {"ownerKind", collaboration_owner_kind(socket), "owner_kind_mismatch"},
      {"ownerId", socket.assigns.device_id, "owner_id_mismatch"},
      {"authorityKind", context.kind, "authority_kind_mismatch"},
      {"authorityId", context.authority_id || public_data["authorityId"],
       "authority_id_mismatch"},
      {"authorityContextKey", context.context_key, "authority_context_key_mismatch"},
      {"authorityScopeId", context.scope_id, "authority_scope_id_mismatch"},
      {"authorityPermissionVersion", authority_permission_version(socket),
       "authority_permission_version_mismatch"}
    ]
  end

  defp authority_context(socket) do
    if share_authority?(socket),
      do: share_authority_context(socket),
      else: workspace_authority_context(socket)
  end

  defp share_authority?(socket),
    do: socket.assigns[:session_kind] == :share_participant

  defp share_authority_context(socket) do
    %{
      kind: "share_participant_device",
      authority_id: socket.assigns.current_share_id,
      context_key: "#{socket.assigns.current_share_id}:#{share_authority_principal_id(socket)}",
      scope_id: socket.assigns.current_share_id
    }
  end

  defp workspace_authority_context(socket) do
    workspace_id = socket.assigns[:document] && socket.assigns.document.workspace_id

    %{
      kind: "workspace_device",
      authority_id: workspace_id,
      context_key: socket.assigns.device_signing_key_id,
      scope_id: workspace_id
    }
  end

  defp authority_permission_version(socket),
    do: socket.assigns[:authority_permission_version] || 1

  defp validate_snapshot_lineage(public_data) do
    with :ok <- validate_parent_snapshot_id(public_data["parentSnapshotId"]),
         :ok <- validate_parent_proof_hash(public_data["parentProofHash"]) do
      validate_parent_snapshot_clocks(public_data["parentSnapshotUpdateClocks"])
    end
  end

  defp validate_parent_snapshot_id("GENESIS"), do: :ok

  defp validate_parent_snapshot_id(v) when is_binary(v) do
    case Ecto.UUID.cast(v) do
      {:ok, _} -> :ok
      :error -> {:error, "invalid_parentSnapshotId"}
    end
  end

  defp validate_parent_snapshot_id(_), do: {:error, "invalid_parentSnapshotId"}

  defp validate_parent_proof_hash(proof) when is_binary(proof), do: :ok
  defp validate_parent_proof_hash(_), do: {:error, "invalid_parentProofHash"}

  defp validate_parent_snapshot_clocks(clocks) when is_map(clocks) do
    if Enum.all?(clocks, fn {_k, v} -> is_integer(v) end) do
      :ok
    else
      {:error, "invalid_parentSnapshotUpdateClocks"}
    end
  end

  defp validate_parent_snapshot_clocks(_), do: {:error, "invalid_parentSnapshotUpdateClocks"}

  defp validate_admission_artifacts(payload) do
    with {:ok, admission} <- validate_map(payload["admission"], "admission"),
         :ok <-
           validate_exact_keys(admission, [
             "workspaceKeyDirectoryCheckpoint",
             "workspaceKeyDirectoryEvents",
             "workspaceKeyDirectoryCheckpointAncestry",
             "workspaceKeyDirectoryEventAncestry"
           ]),
         {:ok, events} <- validate_admission_events(admission["workspaceKeyDirectoryEvents"]),
         {:ok, checkpoint} <-
           validate_map(
             admission["workspaceKeyDirectoryCheckpoint"],
             "workspaceKeyDirectoryCheckpoint"
           ),
         {:ok, checkpoint_ancestry} <-
           validate_optional_admission_envelopes(
             admission["workspaceKeyDirectoryCheckpointAncestry"],
             "invalid_workspaceKeyDirectoryCheckpointAncestry"
           ),
         {:ok, event_ancestry} <-
           validate_optional_admission_envelopes(
             admission["workspaceKeyDirectoryEventAncestry"],
             "invalid_workspaceKeyDirectoryEventAncestry"
           ) do
      {:ok,
       %{
         "workspaceKeyDirectoryEvents" => events,
         "workspaceKeyDirectoryCheckpoint" => checkpoint,
         "workspaceKeyDirectoryCheckpointAncestry" => checkpoint_ancestry,
         "workspaceKeyDirectoryEventAncestry" => event_ancestry
       }}
    end
  end

  defp validate_optional_admission_envelopes(nil, _error), do: {:ok, []}

  defp validate_optional_admission_envelopes([%{} | _] = envelopes, error) do
    if Enum.all?(envelopes, &is_map/1), do: {:ok, envelopes}, else: {:error, error}
  end

  defp validate_optional_admission_envelopes([], _error), do: {:ok, []}
  defp validate_optional_admission_envelopes(_, error), do: {:error, error}

  defp validate_admission_events([%{} | _] = events) do
    if Enum.all?(events, &is_map/1) do
      {:ok, events}
    else
      {:error, "invalid_workspaceKeyDirectoryEvents"}
    end
  end

  defp validate_admission_events(_), do: {:error, "invalid_workspaceKeyDirectoryEvents"}

  defp validate_key_checkpoint_fields(public_data) do
    with :ok <- validate_integer_field(public_data, "keyCheckpointSequence"),
         do: validate_hash_field(public_data, "keyCheckpointHash")
  end

  defp validate_workspace_event_head_fields(public_data) do
    with :ok <- validate_integer_field(public_data, "workspaceEventHeadSequence"),
         do: validate_hash_field(public_data, "workspaceEventHeadHash")
  end

  defp validate_key_checkpoint_boundary(public_data, admission) do
    [event | _] = admission["workspaceKeyDirectoryEvents"]
    body = get_in(event, ["payload", "body"])
    checkpoint_payload = get_in(admission, ["workspaceKeyDirectoryCheckpoint", "payload"])

    cond do
      not is_map(body) or not is_map(checkpoint_payload) ->
        {:error, "invalid_key_checkpoint_boundary"}

      checkpoint_payload["sequence"] != public_data["keyCheckpointSequence"] + 1 ->
        {:error, "key_checkpoint_sequence_mismatch"}

      checkpoint_payload["previous_checkpoint_hash"] != public_data["keyCheckpointHash"] ->
        {:error, "key_checkpoint_hash_mismatch"}

      true ->
        :ok
    end
  end

  defp authority_boundary(parsed, event_type) do
    event =
      Enum.find(parsed.admission["workspaceKeyDirectoryEvents"], fn
        %{"payload" => %{"event_type" => ^event_type}} -> true
        _ -> false
      end) || raise ArgumentError, "document_admission_event_missing"

    body = get_in(event, ["payload", "body"])
    if not is_map(body), do: raise(ArgumentError, "document_admission_body_invalid")

    %{
      "previous_workspace_event_sequence" => body["previous_workspace_event_sequence"],
      "previous_workspace_event_hash" => body["previous_workspace_event_hash"],
      "admission_event_type" => event_type,
      "admission_nonce" => body["admission_nonce"],
      "min_dek_version" => body["min_dek_version"],
      "document_permission_proof_hash" => body["document_permission_proof_hash"]
    }
  end

  defp write_session_authority_boundary(workspace_id, parsed) do
    payload = admission_payload!(parsed.admission, "document_write_session_admitted")
    body = Map.fetch!(payload, "body")

    %{
      "write_session_event_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(payload)),
      "write_session_id" => body["session_id"],
      "write_session_counter" => parsed.public_data["writeSessionCounter"],
      "min_dek_version" => body["min_dek_version"],
      "document_permission_proof_hash" =>
        document_permission_proof_hash(workspace_id, parsed.public_data)
    }
  end

  defp admission_event_body!(admission, event_type) do
    admission
    |> admission_payload!(event_type)
    |> Map.fetch!("body")
  end

  defp admission_payload!(admission, event_type) do
    (admission["workspaceKeyDirectoryEvents"] || admission[:workspaceKeyDirectoryEvents])
    |> Enum.find_value(fn
      %{"payload" => %{"event_type" => ^event_type} = payload} -> payload
      %{payload: %{"event_type" => ^event_type} = payload} -> payload
      _ -> nil
    end)
    |> case do
      nil -> raise ArgumentError, "document_admission_event_missing"
      payload -> payload
    end
  end

  defp document_permission_proof_hash(workspace_id, public_data) do
    %{
      "protocol" => "refmd.document-permission-proof",
      "version" => 1,
      "workspace_id" => workspace_id,
      "document_id" => public_data["docId"],
      "authority_kind" => public_data["authorityKind"],
      "authority_id" => public_data["authorityId"],
      "authority_context_key" => public_data["authorityContextKey"],
      "authority_scope_id" => public_data["authorityScopeId"],
      "authority_permission_version" => public_data["authorityPermissionVersion"],
      "permission" => "edit"
    }
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  defp ephemeral_authority_boundary(workspace_id, public_data) do
    actor_active_proof =
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.editor-ephemeral-actor-active-proof",
        "version" => 1,
        "owner_kind" => public_data["ownerKind"],
        "owner_id" => public_data["ownerId"],
        "authority_kind" => public_data["authorityKind"],
        "authority_id" => public_data["authorityId"],
        "authority_context_key" => public_data["authorityContextKey"],
        "key_checkpoint_sequence" => public_data["keyCheckpointSequence"],
        "key_checkpoint_hash" => public_data["keyCheckpointHash"],
        "signing_key_id" => public_data["signingKeyId"]
      })

    permission_proof =
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.document-permission-proof",
        "version" => 1,
        "workspace_id" => workspace_id,
        "document_id" => public_data["docId"],
        "authority_kind" => public_data["authorityKind"],
        "authority_id" => public_data["authorityId"],
        "authority_context_key" => public_data["authorityContextKey"],
        "authority_scope_id" => public_data["authorityScopeId"],
        "authority_permission_version" => public_data["authorityPermissionVersion"],
        "permission" => "edit"
      })

    %{
      "workspace_event_head_sequence" => public_data["workspaceEventHeadSequence"],
      "workspace_event_head_hash" => public_data["workspaceEventHeadHash"],
      "actor_active_proof_hash" => Hash.blake3_base64url(actor_active_proof),
      "document_permission_proof_hash" => Hash.blake3_base64url(permission_proof),
      "expires_event_sequence" => public_data["workspaceEventHeadSequence"] + 1
    }
  end

  defp validate_hash_field(public_data, field) do
    case public_data[field] do
      v when is_binary(v) ->
        Hash.assert_blake3_base64url!(v)
        :ok

      nil ->
        {:error, "missing_#{field}"}

      _ ->
        {:error, "invalid_#{field}"}
    end
  rescue
    ArgumentError -> {:error, "invalid_#{field}"}
  end

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
        {:ok, Encoding.decode_base64url!(val)}
    end
  rescue
    ArgumentError -> {:error, "invalid_#{key}"}
  end
end
