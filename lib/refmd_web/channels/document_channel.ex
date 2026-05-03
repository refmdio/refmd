defmodule RefMDWeb.DocumentChannel do
  @moduledoc """
  Phoenix Channel for real-time document collaboration.
  Handles document:{document_id} topics with PoP verification and RBAC.
  """

  use Phoenix.Channel

  alias RefMD.Documents
  alias RefMD.Documents.Server, as: DocumentServer
  alias RefMD.Sharing
  alias RefMDWeb.Channels.Document.{Access, Bootstrap, ConnectionManager, Envelope, Pop}
  alias RefMDWeb.TokenBucket

  @ephemeral_rate 10.0
  @ephemeral_burst 20.0
  @share_access_revalidation_ms 60_000

  intercept ["update", "snapshot", "ephemeral-message", "peer-left"]

  @impl true
  @spec join(String.t(), map(), Phoenix.Socket.t()) ::
          {:ok, map(), Phoenix.Socket.t()} | {:error, map()}
  def join("document:" <> document_id, params, socket) do
    user_id = socket.assigns.current_user_id
    silent = silent_join?(params)
    share_session? = socket.assigns[:session_kind] == :share_participant

    with {:ok, document_id} <- cast_uuid(document_id),
         {:ok, device} <- Pop.verify(params, user_id, socket),
         :ok <- Access.subscribe_device_revocation(socket),
         {:ok, document} <- fetch_document(document_id),
         {:ok, mounted_share_id} <- Access.resolve_mounted_share_id(params, user_id, document.id),
         :ok <- Access.check_join(document, user_id, socket, mounted_share_id),
         :ok <-
           Access.maybe_subscribe_share_document_revocation(
             socket.assigns[:current_share_id] || mounted_share_id,
             document.id
           ),
         :ok <- Bootstrap.validate_join_params(params),
         {:ok, server_pid} <- DocumentServer.get_or_start(document.id),
         :ok <- enforce_connection_cap(silent, share_session?, document.id, user_id),
         {:ok, track_join_ref} <-
           track_document_join(
             silent,
             share_session?,
             document.id,
             user_id,
             socket.assigns[:current_share_id],
             device.signing_public_key
           ),
         {:ok, initial_data} <-
           Bootstrap.load_for_join(
             document,
             params,
             socket,
             mounted_share_id,
             user_id
           ) do
      Process.monitor(server_pid)

      if !silent do
        DocumentServer.register_connection(document.id, self())
      end

      socket =
        socket
        |> assign(:document_id, document.id)
        |> assign(:document, document)
        |> assign(:device_id, device.id)
        |> assign(:current_share_id, socket.assigns[:current_share_id] || mounted_share_id)
        |> assign(:mount_id, params["mount_id"])
        |> assign(:mounted_share_id, mounted_share_id)
        |> assign(:device_signing_pub_key_raw, device.signing_public_key)
        |> assign(
          :device_signing_pub_key,
          Base.url_encode64(device.signing_public_key, padding: false)
        )
        |> assign(:ephemeral_bucket, TokenBucket.new(@ephemeral_burst))
        |> assign(:silent, silent)
        |> assign(:track_join_ref, track_join_ref)

      connection_id = Base.url_encode64(:erlang.term_to_binary(self()), padding: false)

      socket = assign(socket, :connection_id, connection_id)

      if share_session?, do: Sharing.touch_participant_session(socket.assigns.current_session.id)
      if share_session? or is_binary(mounted_share_id), do: schedule_share_access_revalidation()

      send(self(), {:after_join, initial_data})
      {:ok, %{connectionId: connection_id}, socket}
    else
      {:error, _reason} = err ->
        if !silent, do: ConnectionManager.cleanup_connection_on_join_failure(document_id)

        err
    end
  end

  @impl true
  @spec handle_info({:after_join, map()}, Phoenix.Socket.t()) ::
          {:noreply, Phoenix.Socket.t()}
  def handle_info({:after_join, initial_data}, socket) do
    push(socket, "document", initial_data)
    {:noreply, socket}
  end

  def handle_info({:evict_connection, join_ref}, socket) do
    if socket.assigns[:track_join_ref] == join_ref do
      push(socket, "connection-cap-evict", %{})
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, socket) do
    {:stop, :normal, socket}
  end

  def handle_info(:connection_cap_evict, socket) do
    push(socket, "connection-cap-evict", %{})
    {:stop, :normal, socket}
  end

  def handle_info({:device_revoked, device_id}, socket) do
    if device_id == socket.assigns.device_id do
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_info({:share_document_revoked, share_id, document_id}, socket) do
    if socket.assigns.current_share_id == share_id and
         socket.assigns.document_id == document_id do
      push(socket, "unauthorized", %{})
      {:stop, :normal, socket}
    else
      {:noreply, socket}
    end
  end

  def handle_info(
        :share_access_revalidation,
        %{assigns: %{mounted_share_id: mounted_share_id}} = socket
      )
      when is_binary(mounted_share_id) do
    if Access.mounted_share_still_authorized?(socket) do
      schedule_share_access_revalidation()
      {:noreply, socket}
    else
      push(socket, "unauthorized", %{})
      {:stop, :normal, socket}
    end
  end

  def handle_info(
        :share_access_revalidation,
        %{assigns: %{session_kind: :share_participant}} = socket
      ) do
    if Access.share_session_still_authorized?(socket) do
      schedule_share_access_revalidation()
      {:noreply, socket}
    else
      push(socket, "unauthorized", %{})
      {:stop, :normal, socket}
    end
  end

  @impl true
  @spec handle_in(String.t(), map(), Phoenix.Socket.t()) ::
          {:reply, {:ok | :error, map()}, Phoenix.Socket.t()} | {:noreply, Phoenix.Socket.t()}
  def handle_in(_event, _payload, %{assigns: %{silent: true}} = socket) do
    {:reply, {:error, %{reason: "silent_connection"}}, socket}
  end

  def handle_in("update", payload, socket) do
    with {:ok, parsed} <- Envelope.parse_update_envelope(payload, socket),
         :ok <-
           Envelope.verify_envelope_signature("refmd_update", payload, parsed, socket),
         :ok <- Envelope.verify_update_hash(parsed, socket),
         :ok <- Access.validate_write(socket),
         :ok <- Access.validate_device_active(socket) do
      result =
        Documents.save_update(
          socket.assigns.document_id,
          socket.assigns.current_user_id,
          update_attrs(socket, parsed)
        )

      handle_update_result(result, parsed, payload, socket)
    else
      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  def handle_in("snapshot", payload, socket) do
    with {:ok, parsed} <- Envelope.parse_snapshot_envelope(payload, socket),
         :ok <-
           Envelope.verify_envelope_signature("refmd_snapshot", payload, parsed, socket),
         :ok <- Access.validate_write(socket),
         :ok <- Access.validate_device_active(socket) do
      result =
        Documents.save_snapshot(
          socket.assigns.document_id,
          socket.assigns.current_user_id,
          snapshot_attrs(socket, parsed)
        )

      case result do
        {:ok, saved} ->
          DocumentServer.set_active_snapshot(
            socket.assigns.document_id,
            saved.snapshot_id,
            %{}
          )

          push(socket, "snapshot-saved", %{
            snapshotId: saved.snapshot_id,
            latestVersion: saved.latest_version
          })

          broadcast_from(socket, "snapshot", %{
            snapshotId: saved.snapshot_id,
            snapshot: payload
          })

          {:noreply, socket}

        {:error, reason, recovery}
        when reason in [:parent_mismatch, :clocks_mismatch, :key_version_too_old] ->
          failure_data =
            Envelope.build_snapshot_failure(
              recovery,
              socket.assigns.document_id,
              parsed.public_data["parentSnapshotId"]
            )

          push(socket, "snapshot-save-failed", failure_data)
          {:noreply, socket}

        {:error, :serialization_conflict, recovery} ->
          failure_data =
            Envelope.build_snapshot_failure(
              recovery,
              socket.assigns.document_id,
              parsed.public_data["parentSnapshotId"]
            )

          push(socket, "snapshot-save-failed", failure_data)
          {:noreply, socket}

        {:error, :document_archived, _} ->
          {:reply, {:error, %{reason: "document_archived"}}, socket}

        {:error, :permission_denied, _} ->
          {:reply, {:error, %{reason: "permission_denied"}}, socket}

        {:error, :device_revoked, _} ->
          {:reply, {:error, %{reason: "device_revoked"}}, socket}

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

        with {:ok, parsed} <- Envelope.parse_ephemeral_envelope(payload, socket),
             :ok <-
               Envelope.verify_envelope_signature(
                 "refmd_ephemeral",
                 payload,
                 parsed,
                 socket
               ),
             :ok <- Access.validate_device_active(socket),
             :ok <- Access.check_ephemeral(socket) do
          broadcast_from(socket, "ephemeral-message", payload)
          {:noreply, socket}
        else
          {:error, reason} ->
            {:reply, {:error, %{reason: reason}}, socket}
        end
    end
  end

  @impl true
  def handle_out(_event, _payload, %{assigns: %{silent: true}} = socket) do
    {:noreply, socket}
  end

  def handle_out(event, payload, socket)
      when event in ["update", "snapshot", "ephemeral-message", "peer-left"] do
    case Access.check_broadcast(socket) do
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
    cleanup_on_terminate(socket)
    :ok
  end

  # ── Connection Lifecycle ──────────────────────

  defp cleanup_on_terminate(%{assigns: %{document_id: _document_id, silent: true}} = _socket) do
    :ok
  end

  defp cleanup_on_terminate(%{assigns: %{document_id: document_id}} = socket) do
    DocumentServer.unregister_connection(document_id, self())
    ConnectionManager.cleanup_connection(document_id)

    ConnectionManager.broadcast_peer_left(
      document_id,
      socket.assigns[:device_signing_pub_key],
      socket.assigns[:current_user_id],
      socket.assigns[:connection_id]
    )
  end

  defp cleanup_on_terminate(_socket), do: :ok

  defp schedule_share_access_revalidation do
    Process.send_after(self(), :share_access_revalidation, @share_access_revalidation_ms)
  end

  defp enforce_connection_cap(true, true, _document_id, _user_id) do
    {:error, %{reason: "silent_share_join_not_supported"}}
  end

  defp enforce_connection_cap(true, _share_session?, _document_id, user_id) do
    ConnectionManager.check_and_increment_silent(user_id)
  end

  defp enforce_connection_cap(false, true, _document_id, _user_id), do: :ok

  defp enforce_connection_cap(false, false, document_id, user_id) do
    ConnectionManager.evict_excess(document_id, user_id)
  end

  defp track_document_join(
         true,
         _share_session?,
         _document_id,
         _user_id,
         _share_id,
         _signing_public_key
       ),
       do: {:ok, nil}

  defp track_document_join(
         false,
         true,
         document_id,
         principal_id,
         share_id,
         signing_public_key
       )
       when is_binary(share_id) do
    ConnectionManager.track_share_connection(
      document_id,
      share_id,
      principal_id,
      Base.url_encode64(signing_public_key, padding: false)
    )
  end

  defp track_document_join(false, false, document_id, user_id, _share_id, signing_public_key) do
    ConnectionManager.track_and_subscribe(
      document_id,
      user_id,
      Base.url_encode64(signing_public_key, padding: false)
    )
  end

  defp silent_join?(%{"silent" => true}), do: true
  defp silent_join?(_params), do: false

  defp cast_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
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

  # ── Update/Snapshot Result Handlers ───────────

  defp update_attrs(socket, parsed) do
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
    |> maybe_put_share_context(socket)
  end

  defp snapshot_attrs(socket, parsed) do
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
    |> maybe_put_share_context(socket)
  end

  defp maybe_put_share_context(attrs, socket) do
    cond do
      socket.assigns[:session_kind] == :share_participant ->
        Map.merge(attrs, %{
          session_kind: :share_participant,
          share_id: socket.assigns.current_share_id,
          grant: socket.assigns.share_participant_grant,
          principal_id: socket.assigns.share_participant_principal_id
        })

      is_binary(socket.assigns[:mounted_share_id]) ->
        Map.merge(attrs, %{
          session_kind: :mounted_share,
          share_id: socket.assigns.current_share_id,
          grant: "edit",
          principal_id: socket.assigns.current_user_id
        })

      true ->
        attrs
    end
  end

  defp handle_update_result({:ok, saved}, _parsed, payload, socket) do
    maybe_broadcast_update(saved, payload, socket)

    push(socket, "update-saved", %{
      snapshotId: saved.snapshot_id,
      clock: saved.clock,
      updateHash: saved.update_hash,
      version: saved.version
    })

    {:noreply, socket}
  end

  defp handle_update_result({:error, :snapshot_mismatch}, parsed, _payload, socket) do
    push(socket, "update-save-failed", %{
      snapshotId: parsed.public_data["refSnapshotId"],
      clock: parsed.public_data["clock"],
      requiresNewSnapshot: true
    })

    {:noreply, socket}
  end

  defp handle_update_result({:error, reason}, parsed, _payload, socket)
       when reason in [:key_version_too_old, :clock_mismatch, :serialization_conflict] do
    push(socket, "update-save-failed", %{
      snapshotId: parsed.public_data["refSnapshotId"],
      clock: parsed.public_data["clock"],
      requiresNewSnapshot: false
    })

    {:noreply, socket}
  end

  defp handle_update_result({:error, reason}, _parsed, _payload, socket)
       when reason in [:document_archived, :permission_denied, :device_revoked] do
    {:reply, {:error, %{reason: to_string(reason)}}, socket}
  end

  defp handle_update_result({:error, _reason}, _parsed, _payload, socket) do
    {:reply, {:error, %{reason: "error"}}, socket}
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
end
