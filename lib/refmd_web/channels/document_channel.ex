defmodule RefMDWeb.DocumentChannel do
  @moduledoc """
  Phoenix Channel for real-time document collaboration.
  Handles document:{document_id} topics with PoP verification and RBAC.
  """

  use Phoenix.Channel

  alias RefMD.Auth
  alias RefMD.Devices
  alias RefMD.Documents
  alias RefMD.Documents.Server, as: DocumentServer
  alias RefMD.Workspaces
  alias RefMDWeb.{DocumentPresence, TokenBucket}
  alias RefMDWeb.Plugs.RequireRBAC

  @ephemeral_rate 10.0
  @ephemeral_burst 20.0
  @max_connections_per_user 3

  intercept ["update", "snapshot", "ephemeral-message"]

  @impl true
  @spec join(String.t(), map(), Phoenix.Socket.t()) ::
          {:ok, map(), Phoenix.Socket.t()} | {:error, map()}
  def join("document:" <> document_id, params, socket) do
    user_id = socket.assigns.current_user_id

    with :ok <- validate_uuid(document_id),
         :ok <- reject_silent_join(params),
         {:ok, device} <- verify_pop(params, user_id, socket),
         :ok <- subscribe_device_revocation(user_id),
         {:ok, document} <- fetch_document(document_id),
         :ok <- check_rbac(document.workspace_id, user_id),
         :ok <- validate_join_params(params),
         {:ok, server_pid} <- DocumentServer.get_or_start(document.id),
         :ok <- maybe_enforce_connection_cap(document.id, user_id, params),
         :ok <- DocumentServer.register_connection(document.id, self()),
         {:ok, initial_data} <-
           load_initial_data(document, params, document.workspace_id, user_id) do
      Process.monitor(server_pid)

      socket =
        socket
        |> assign(:document_id, document.id)
        |> assign(:document, document)
        |> assign(:device_id, device.id)
        |> assign(:device_signing_pub_key_raw, device.signing_public_key)
        |> assign(
          :device_signing_pub_key,
          Base.url_encode64(device.signing_public_key, padding: false)
        )
        |> assign(:ephemeral_bucket, TokenBucket.new(@ephemeral_burst))

      send(self(), {:after_join, initial_data})
      {:ok, %{}, socket}
    end
  end

  @impl true
  @spec handle_info({:after_join, map()}, Phoenix.Socket.t()) ::
          {:noreply, Phoenix.Socket.t()}
  def handle_info({:after_join, initial_data}, socket) do
    push(socket, "document", initial_data)
    {:noreply, socket}
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, socket) do
    {:stop, :normal, socket}
  end

  def handle_info(:connection_cap_evict, socket) do
    {:stop, :normal, socket}
  end

  def handle_info({:device_revoked, device_id}, socket) do
    if device_id == socket.assigns.device_id do
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  @spec handle_in(String.t(), map(), Phoenix.Socket.t()) ::
          {:reply, {:ok | :error, map()}, Phoenix.Socket.t()} | {:noreply, Phoenix.Socket.t()}
  def handle_in("update", payload, socket) do
    with {:ok, parsed} <- parse_update_envelope(payload, socket),
         :ok <- verify_envelope_signature("refmd_update", payload, parsed, socket),
         :ok <- verify_update_hash(parsed, socket),
         :ok <- validate_device_active(socket) do
      result =
        Documents.save_update(
          socket.assigns.document_id,
          socket.assigns.current_user_id,
          %{
            ref_snapshot_id: parsed.public_data["refSnapshotId"],
            device_id: socket.assigns.device_id,
            clock: parsed.public_data["clock"],
            device_signing_pub_key: socket.assigns.device_signing_pub_key,
            update_data: parsed.ciphertext_raw,
            nonce: parsed.nonce_raw,
            key_version: parsed.public_data["keyVersion"],
            update_hash: parsed.public_data["updateHash"],
            signature: parsed.signature_raw,
            timestamp: parsed.public_data["timestamp"]
          }
        )

      case result do
        {:ok, saved} ->
          maybe_broadcast_update(saved, payload, socket)

          push(socket, "update-saved", %{
            snapshotId: saved.snapshot_id,
            clock: saved.clock,
            version: saved.version
          })

          {:noreply, socket}

        {:error, :snapshot_mismatch} ->
          push(socket, "update-save-failed", %{
            snapshotId: parsed.public_data["refSnapshotId"],
            clock: parsed.public_data["clock"],
            requiresNewSnapshot: true
          })

          {:noreply, socket}

        {:error, :key_version_too_old} ->
          push(socket, "update-save-failed", %{
            snapshotId: parsed.public_data["refSnapshotId"],
            clock: parsed.public_data["clock"],
            requiresNewSnapshot: false
          })

          {:noreply, socket}

        {:error, :clock_mismatch} ->
          push(socket, "update-save-failed", %{
            snapshotId: parsed.public_data["refSnapshotId"],
            clock: parsed.public_data["clock"],
            requiresNewSnapshot: false
          })

          {:noreply, socket}

        {:error, :serialization_conflict} ->
          push(socket, "update-save-failed", %{
            snapshotId: parsed.public_data["refSnapshotId"],
            clock: parsed.public_data["clock"],
            requiresNewSnapshot: false
          })

          {:noreply, socket}

        {:error, :document_archived} ->
          {:reply, {:error, %{reason: "document_archived"}}, socket}

        {:error, _reason} ->
          {:reply, {:error, %{reason: "error"}}, socket}
      end
    else
      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  def handle_in("snapshot", payload, socket) do
    with {:ok, parsed} <- parse_snapshot_envelope(payload, socket),
         :ok <- verify_envelope_signature("refmd_snapshot", payload, parsed, socket),
         :ok <- validate_device_active(socket) do
      result =
        Documents.save_snapshot(
          socket.assigns.document_id,
          socket.assigns.current_user_id,
          %{
            snapshot_id: parsed.public_data["snapshotId"],
            parent_snapshot_id: parsed.public_data["parentSnapshotId"],
            device_id: socket.assigns.device_id,
            data: parsed.ciphertext_raw,
            nonce: parsed.nonce_raw,
            key_version: parsed.public_data["keyVersion"],
            signature: parsed.signature_raw,
            parent_snapshot_proof: parsed.public_data["parentSnapshotProof"],
            parent_snapshot_update_clocks: parsed.public_data["parentSnapshotUpdateClocks"],
            created_by_device: socket.assigns.device_signing_pub_key
          }
        )

      case result do
        {:ok, saved} ->
          DocumentServer.set_active_snapshot(
            socket.assigns.document_id,
            saved.snapshot_id,
            %{}
          )

          push(socket, "snapshot-saved", %{snapshotId: saved.snapshot_id})

          broadcast_from(socket, "snapshot", %{
            snapshotId: saved.snapshot_id,
            snapshot: payload
          })

          {:noreply, socket}

        {:error, reason, recovery}
        when reason in [:parent_mismatch, :clocks_mismatch, :key_version_too_old] ->
          failure_data =
            build_snapshot_failure(
              recovery,
              socket.assigns.document_id,
              parsed.public_data["parentSnapshotId"]
            )

          push(socket, "snapshot-save-failed", failure_data)
          {:noreply, socket}

        {:error, :serialization_conflict, recovery} ->
          failure_data =
            build_snapshot_failure(
              recovery,
              socket.assigns.document_id,
              parsed.public_data["parentSnapshotId"]
            )

          push(socket, "snapshot-save-failed", failure_data)
          {:noreply, socket}

        {:error, :document_archived, _} ->
          {:reply, {:error, %{reason: "document_archived"}}, socket}

        {:error, _reason, _} ->
          {:reply, {:error, %{reason: "error"}}, socket}
      end
    else
      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  def handle_in("ephemeral", payload, socket) do
    case TokenBucket.check(socket.assigns.ephemeral_bucket, @ephemeral_rate, @ephemeral_burst) do
      {:drop, bucket} ->
        {:noreply, assign(socket, :ephemeral_bucket, bucket)}

      {:ok, bucket} ->
        socket = assign(socket, :ephemeral_bucket, bucket)

        with {:ok, parsed} <- parse_ephemeral_envelope(payload, socket),
             :ok <- verify_envelope_signature("refmd_ephemeral", payload, parsed, socket),
             :ok <- validate_device_active(socket),
             :ok <- check_ephemeral_rbac(socket) do
          broadcast_from(socket, "ephemeral-message", payload)
          {:noreply, socket}
        else
          {:error, reason} ->
            {:reply, {:error, %{reason: reason}}, socket}
        end
    end
  end

  @impl true
  def handle_out(event, payload, socket)
      when event in ["update", "snapshot", "ephemeral-message"] do
    case check_broadcast_rbac(socket) do
      :ok ->
        push(socket, event, payload)
        {:noreply, socket}

      :evict ->
        push(socket, "unauthorized", %{})
        {:stop, :normal, socket}

      :skip ->
        {:noreply, socket}
    end
  end

  @impl true
  def terminate(_reason, socket) do
    if document_id = socket.assigns[:document_id] do
      DocumentServer.unregister_connection(document_id, self())
    end

    :ok
  end

  # ── Join Helpers ────────────────────────────────

  defp check_ephemeral_rbac(socket) do
    case check_broadcast_rbac(socket) do
      :ok -> :ok
      :evict -> {:error, "permission_denied"}
      :skip -> {:error, "permission_check_failed"}
    end
  end

  defp check_broadcast_rbac(socket) do
    workspace_id = socket.assigns.document.workspace_id
    user_id = socket.assigns.current_user_id

    try do
      case Workspaces.get_member_with_role(workspace_id, user_id) do
        nil ->
          :evict

        {_member, role} ->
          perms = RequireRBAC.effective_permissions(role)

          if MapSet.member?(perms, "document:read") do
            :ok
          else
            :evict
          end
      end
    rescue
      _ -> :skip
    end
  end

  defp maybe_enforce_connection_cap(document_id, user_id, _params) do
    enforce_connection_cap(document_id, user_id)
  end

  defp enforce_connection_cap(document_id, user_id) do
    topic = "document:#{document_id}"
    evict_excess_connections(topic, user_id, @max_connections_per_user)

    {:ok, _} =
      DocumentPresence.track(self(), topic, user_id, %{
        pid: self(),
        joined_at: System.monotonic_time(:millisecond)
      })

    :ok
  end

  defp evict_excess_connections(topic, user_id, max) do
    presences = DocumentPresence.list(topic)
    user_metas = get_in(presences, [user_id, :metas]) || []

    if length(user_metas) >= max do
      oldest = hd(user_metas)
      oldest_pid = oldest[:pid]
      if oldest_pid, do: send(oldest_pid, :connection_cap_evict)
    end
  end

  defp reject_silent_join(%{"silent" => true}),
    do: {:error, %{reason: "silent_join_not_supported"}}

  defp reject_silent_join(_params), do: :ok

  defp subscribe_device_revocation(user_id) do
    Phoenix.PubSub.subscribe(RefMD.PubSub, "device_revocation:#{user_id}")
    :ok
  end

  defp validate_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, _} -> :ok
      :error -> {:error, %{reason: "invalid_id"}}
    end
  end

  defp fetch_document(document_id) do
    case Documents.get_document(document_id) do
      nil -> {:error, %{reason: "document_not_found"}}
      %{doc_type: "folder"} -> {:error, %{reason: "folder_not_editable"}}
      document -> {:ok, document}
    end
  end

  defp verify_pop(params, user_id, socket) do
    session = socket.assigns.current_session

    with {:ok, device_id} <- get_session_device_id(session),
         {:ok, challenge} <- decode_param(params, "pop_challenge"),
         {:ok, signature} <- decode_param(params, "pop_signature"),
         {:ok, device} <- get_active_device(user_id, device_id),
         :ok <- verify_pop_signature(challenge, signature, device),
         :ok <- Auth.consume_pop_challenge(challenge, user_id, device.id) do
      {:ok, device}
    else
      {:error, _reason} -> {:error, %{reason: "pop_verification_failed"}}
    end
  end

  defp get_session_device_id(session) do
    case Auth.get_session(session.id) do
      %{device_id: nil} -> {:error, :unbound_session}
      %{device_id: id} -> {:ok, id}
      nil -> {:error, :session_expired}
    end
  end

  defp get_active_device(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_pop_signature(challenge, signature, device) do
    message =
      RefMD.Crypto.build_signature_message("pop_challenge", %{
        "challenge" => Base.url_encode64(challenge, padding: false),
        "device_id" => device.id
      })

    if RefMD.Crypto.verify_ed25519_signature(message, signature, device.signing_public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp validate_join_params(%{"mode" => "delta"} = params) do
    with :ok <- validate_optional_join_uuid(params, "knownSnapshotId") do
      case params["knownSnapshotUpdateClocks"] do
        clocks when is_map(clocks) -> validate_clock_values(clocks)
        _ -> {:error, %{reason: "knownSnapshotUpdateClocks required for delta mode"}}
      end
    end
  end

  defp validate_join_params(%{"mode" => "complete"} = params),
    do: validate_optional_join_uuid(params, "knownSnapshotId")

  defp validate_join_params(%{"mode" => nil} = params),
    do: validate_optional_join_uuid(params, "knownSnapshotId")

  defp validate_join_params(%{"mode" => _}), do: {:error, %{reason: "invalid mode"}}
  defp validate_join_params(params), do: validate_optional_join_uuid(params, "knownSnapshotId")

  defp validate_optional_join_uuid(params, key) do
    case params[key] do
      nil ->
        :ok

      v when is_binary(v) ->
        case Ecto.UUID.cast(v) do
          {:ok, _} -> :ok
          :error -> {:error, %{reason: "invalid_#{key}"}}
        end

      _ ->
        {:error, %{reason: "invalid_#{key}"}}
    end
  end

  defp validate_clock_values(clocks) do
    if Enum.all?(clocks, fn {_k, v} -> is_integer(v) end) do
      :ok
    else
      {:error, %{reason: "knownSnapshotUpdateClocks values must be integers"}}
    end
  end

  defp check_rbac(workspace_id, user_id) do
    case Workspaces.get_member_with_role(workspace_id, user_id) do
      nil ->
        {:error, %{reason: "not_a_member"}}

      {_member, role} ->
        perms = RequireRBAC.effective_permissions(role)

        if MapSet.member?(perms, "document:read") do
          :ok
        else
          {:error, %{reason: "permission_denied"}}
        end
    end
  end

  defp load_initial_data(document, params, workspace_id, user_id) do
    mode = params["mode"] || "complete"

    case Documents.get_initial_document_data(document.id, workspace_id, user_id) do
      {:error, :unauthorized} ->
        {:error, %{reason: "permission_denied"}}

      {:error, :db_error} ->
        {:error, %{reason: "document_error"}}

      {:ok, {snapshot, all_updates}} ->
        updates = filter_updates(snapshot, all_updates, mode, params)
        snapshot_id = if snapshot, do: snapshot.id
        delta_same = mode == "delta" && params["knownSnapshotId"] == snapshot_id

        latest_version = if snapshot, do: snapshot.latest_version, else: 0

        proof_chain =
          Documents.build_snapshot_proof_chain(
            document.id,
            params["knownSnapshotId"],
            snapshot_id
          )

        data = %{
          snapshot: if(delta_same, do: nil, else: format_snapshot(snapshot)),
          updates: Enum.map(updates, &format_update/1),
          snapshotProofChain: proof_chain,
          latestVersion: latest_version
        }

        {:ok, data}
    end
  end

  defp filter_updates(_snapshot, updates, "complete", _params), do: updates

  defp filter_updates(snapshot, updates, "delta", params) do
    known_clocks = params["knownSnapshotUpdateClocks"]
    known_snapshot_id = params["knownSnapshotId"]
    same_snapshot = snapshot && known_snapshot_id == snapshot.id

    cond do
      is_nil(snapshot) -> []
      !same_snapshot -> updates
      true -> filter_by_clocks(updates, known_clocks)
    end
  end

  defp filter_updates(_snapshot, updates, _mode, _params), do: updates

  defp filter_by_clocks(updates, known_clocks) do
    Enum.filter(updates, fn u ->
      case u.device_signing_pub_key do
        nil -> true
        pk -> is_nil(u.clock) or u.clock > Map.get(known_clocks, pk, -1)
      end
    end)
  end

  # ── Formatters ─────────────────────────────────

  defp format_snapshot(nil), do: nil

  defp format_snapshot(snap) do
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

  defp format_update(update) do
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

  # ── Update/Snapshot Helpers ───────────────────

  @update_public_data_keys ~w(docId deviceId signingPubKey clock keyVersion timestamp refSnapshotId updateHash)
  @snapshot_public_data_keys ~w(docId deviceId signingPubKey snapshotId keyVersion parentSnapshotId parentSnapshotProof parentSnapshotUpdateClocks)
  @ephemeral_public_data_keys ~w(docId deviceId signingPubKey)

  defp parse_update_envelope(payload, socket) do
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

  defp parse_snapshot_envelope(payload, socket) do
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

  defp verify_envelope_signature(prefix, payload, parsed, socket) do
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

  defp validate_device_active(socket) do
    case Devices.get_device(socket.assigns.device_id) do
      %{user_id: uid, revoked_at: nil} when uid == socket.assigns.current_user_id ->
        :ok

      _ ->
        {:error, "device_revoked"}
    end
  end

  defp maybe_broadcast_update(%{duplicate: true}, _payload, _socket), do: :ok

  defp maybe_broadcast_update(saved, payload, socket) do
    DocumentServer.update_clocks(
      socket.assigns.document_id,
      socket.assigns.device_signing_pub_key,
      saved.clock
    )

    broadcast_envelope = Map.put(payload, "version", saved.version)
    broadcast_from(socket, "update", broadcast_envelope)
  end

  defp verify_update_hash(parsed, socket) do
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

  defp parse_ephemeral_envelope(payload, socket) do
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

  defp validate_device_id(public_data, socket) do
    if public_data["deviceId"] == socket.assigns.device_id do
      :ok
    else
      {:error, "device_id_mismatch"}
    end
  end

  defp build_snapshot_failure(nil, _document_id, _known_snapshot_id) do
    %{snapshot: nil, updates: [], snapshotProofChain: []}
  end

  defp build_snapshot_failure(
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

  # ── Param Helpers ──────────────────────────────

  defp decode_param(params, key) do
    case params[key] do
      nil -> {:error, :"missing_#{key}"}
      val -> Base.url_decode64(val, padding: false) |> wrap_decode_error(key)
    end
  end

  defp wrap_decode_error({:ok, _} = ok, _key), do: ok
  defp wrap_decode_error(:error, key), do: {:error, :"invalid_#{key}"}
end
