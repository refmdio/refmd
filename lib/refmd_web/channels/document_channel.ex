defmodule RefMDWeb.DocumentChannel do
  @moduledoc """
  Phoenix Channel for real-time document collaboration.
  Handles document:{document_id} topics with RRP verification and RBAC.
  """

  use Phoenix.Channel, log_join: false

  alias RefMD.Documents
  alias RefMD.Sharing
  alias RefMDWeb.Channels.Document.{Access, Bootstrap, ConnectionManager, Envelope, Rrp}
  alias RefMDWeb.Channels.TokenBucket

  @ephemeral_rate 10.0
  @ephemeral_burst 20.0
  @share_access_revalidation_ms 60_000
  @max_safe_json_integer 9_007_199_254_740_991
  @strict_json_error_key "_refmd_strict_json_error"

  intercept [
    "update",
    "snapshot",
    "write-session",
    "ephemeral-message",
    "peer-left",
    "public-status-changed"
  ]

  @impl true
  def join("document:" <> document_id, raw_params, socket) do
    user_id = socket.assigns.current_user_id
    share_session? = socket.assigns[:session_kind] == :share_participant

    with {:ok, params} <- strict_join_params(raw_params),
         silent <- silent_join?(params),
         {:ok, document_id} <- cast_uuid(document_id),
         {:ok, document} <- fetch_document(document_id),
         {:ok, mounted_share_id} <-
           Access.resolve_mounted_share_id(params, user_id, document.id, socket),
         {:ok, device} <- Rrp.verify(params, user_id, socket, document_id, mounted_share_id),
         :ok <- Access.subscribe_device_revocation(socket),
         :ok <- Access.check_join(document, user_id, socket, mounted_share_id),
         :ok <-
           Access.maybe_subscribe_share_document_revocation(
             socket.assigns[:current_share_id] || mounted_share_id,
             document.id
           ),
         :ok <-
           Access.maybe_subscribe_share_revocation(
             socket.assigns[:current_share_id] || mounted_share_id
           ),
         :ok <- Bootstrap.validate_join_params(params),
         {:ok, server_pid} <- Documents.get_or_start_server(document.id),
         :ok <- enforce_connection_cap(silent, share_session?, document.id, user_id),
         {:ok, track_join_ref} <-
           track_document_join(
             silent,
             share_session?,
             document.id,
             user_id,
             socket.assigns[:current_share_id],
             Map.get(device, :signing_key_id)
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
        Documents.register_connection(document.id, self())
      end

      socket =
        socket
        |> assign(:document_id, document.id)
        |> assign(:document, document)
        |> assign(:device_id, device.id)
        |> assign(:current_share_id, socket.assigns[:current_share_id] || mounted_share_id)
        |> assign(
          :authority_permission_version,
          Map.get(initial_data, :authorityPermissionVersion, 1)
        )
        |> assign(:mount_id, params["mount_id"])
        |> assign(:mounted_share_id, mounted_share_id)
        |> assign(:workspace_key_directory_pin_anchor, workspace_key_directory_pin_anchor(params))
        |> assign(
          :mounted_trust_anchor,
          %{
            authenticated_workspace_pin_bootstrap_hash:
              params["authenticated_workspace_pin_bootstrap_hash"]
          }
        )
        |> assign(
          :device_hybrid_signing_public_key_material,
          Map.get(device, :hybrid_signing_public_key_material)
        )
        |> assign(:device_signing_key_id, Map.get(device, :signing_key_id))
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
        if !strict_join_silent?(raw_params),
          do: ConnectionManager.cleanup_connection_on_join_failure(document_id)

        err
    end
  end

  @impl true
  def handle_info({:after_join, initial_data}, socket) do
    push(socket, "document", initial_data)
    push_active_write_sessions(socket)
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

  def handle_info({:share_revoked, share_id}, socket) do
    if socket.assigns.current_share_id == share_id do
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
  def handle_in(_event, _payload, %{assigns: %{silent: true}} = socket) do
    {:reply, {:error, %{reason: "silent_connection"}}, socket}
  end

  def handle_in(
        "update",
        %{@strict_json_error_key => "document_update_payload_too_large"},
        socket
      ) do
    failure = %{
      reason: "document_update_payload_too_large",
      requiresNewSnapshot: false
    }

    push(socket, "update-save-failed", failure)
    {:noreply, socket}
  end

  def handle_in("update", payload, socket) do
    with {:ok, payload} <- strict_channel_payload(payload),
         {:ok, parsed} <- Envelope.parse_update_envelope(payload, socket),
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

  def handle_in("write-session", payload, socket) do
    with {:ok, payload} <- strict_channel_payload(payload),
         {:ok, parsed} <- Envelope.parse_write_session_envelope(payload, socket),
         :ok <- Access.validate_write(socket),
         :ok <- Access.validate_device_active(socket) do
      result =
        Documents.admit_write_session(
          socket.assigns.document_id,
          socket.assigns.current_user_id,
          write_session_attrs(socket, parsed)
        )

      handle_write_session_result(result, parsed, socket)
    else
      {:error, reason} ->
        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  def handle_in("snapshot", payload, socket) do
    with {:ok, payload} <- strict_channel_payload(payload),
         {:ok, parsed} <- Envelope.parse_snapshot_envelope(payload, socket),
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

      handle_snapshot_result(result, parsed, socket)
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

        with {:ok, payload} <- strict_channel_payload(payload),
             {:ok, parsed} <- Envelope.parse_ephemeral_envelope(payload, socket),
             :ok <- Access.check_ephemeral(socket),
             :ok <-
               Envelope.verify_envelope_signature(
                 "refmd_ephemeral",
                 payload,
                 parsed,
                 socket
               ),
             :ok <- Access.validate_device_active(socket) do
          broadcast_from(socket, "ephemeral-message", payload)
          {:noreply, socket}
        else
          {:error, reason} ->
            {:reply, {:error, %{reason: reason}}, socket}
        end
    end
  end

  defp strict_join_params(%{"_jcs_payload" => _}), do: {:error, %{reason: "invalid_json"}}

  defp strict_join_params(%{} = params) do
    if strict_json_shape?(params),
      do: {:ok, params},
      else: {:error, %{reason: "invalid_json"}}
  end

  defp strict_join_params(_), do: {:error, %{reason: "invalid_json"}}

  defp strict_join_silent?(raw_params) do
    case strict_join_params(raw_params) do
      {:ok, params} -> silent_join?(params)
      _ -> false
    end
  end

  defp strict_channel_payload(%{"_jcs_payload" => _}), do: {:error, "invalid_strict_json"}

  defp strict_channel_payload(%{} = payload) do
    if strict_json_shape?(payload),
      do: {:ok, payload},
      else: {:error, "invalid_strict_json"}
  end

  defp strict_channel_payload(_), do: {:error, "invalid_strict_json"}

  defp strict_json_shape?(%{} = value) do
    Enum.all?(value, fn
      {key, item} when is_binary(key) -> strict_json_shape?(item)
      _ -> false
    end)
  end

  defp strict_json_shape?(value) when is_list(value), do: Enum.all?(value, &strict_json_shape?/1)
  defp strict_json_shape?(value) when is_binary(value), do: true
  defp strict_json_shape?(value) when is_boolean(value), do: true

  defp strict_json_shape?(value) when is_integer(value),
    do: value >= 0 and value <= @max_safe_json_integer

  defp strict_json_shape?(_value), do: false

  @impl true
  def handle_out(_event, _payload, %{assigns: %{silent: true}} = socket) do
    {:noreply, socket}
  end

  def handle_out(event, payload, socket)
      when event in [
             "update",
             "snapshot",
             "write-session",
             "ephemeral-message",
             "peer-left",
             "public-status-changed"
           ] do
    deliver_broadcast_event(event, payload, socket)
  end

  defp deliver_broadcast_event(event, payload, socket)
       when event in [
              "update",
              "snapshot",
              "write-session",
              "ephemeral-message",
              "peer-left",
              "public-status-changed"
            ] do
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
    Documents.unregister_connection(document_id, self())
    ConnectionManager.cleanup_connection(document_id)

    ConnectionManager.broadcast_peer_left(
      document_id,
      socket.assigns[:device_signing_key_id],
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
         _signing_key_id
       ),
       do: {:ok, nil}

  defp track_document_join(
         false,
         true,
         document_id,
         principal_id,
         share_id,
         signing_key_id
       )
       when is_binary(share_id) do
    ConnectionManager.track_share_connection(
      document_id,
      share_id,
      principal_id,
      signing_key_id
    )
  end

  defp track_document_join(false, false, document_id, user_id, _share_id, signing_key_id) do
    ConnectionManager.track_and_subscribe(
      document_id,
      user_id,
      signing_key_id
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
      workspace_id: socket.assigns.document.workspace_id,
      clock: parsed.public_data["clock"],
      signing_key_id: socket.assigns.device_signing_key_id,
      update_data: parsed.ciphertext_raw,
      nonce: parsed.nonce_raw,
      key_version: parsed.public_data["keyVersion"],
      update_hash: parsed.public_data["updateHash"],
      hybrid_signature: parsed.signature,
      signature_verified: true,
      public_data: parsed.public_data,
      owner_kind: parsed.public_data["ownerKind"],
      owner_id: parsed.public_data["ownerId"],
      authority_kind: parsed.public_data["authorityKind"],
      authority_id: parsed.public_data["authorityId"],
      authority_context_key: parsed.public_data["authorityContextKey"],
      authority_scope_id: parsed.public_data["authorityScopeId"],
      authority_permission_version: parsed.public_data["authorityPermissionVersion"],
      key_checkpoint_sequence: key_checkpoint_sequence(parsed),
      key_checkpoint_hash: key_checkpoint_hash(parsed),
      write_session_counter: parsed.public_data["writeSessionCounter"],
      timestamp: parsed.public_data["timestamp"]
    }
    |> Map.put(:admission, parsed.admission)
    |> Map.put(:admission_actor, admission_actor(socket, parsed))
    |> maybe_put_share_context(socket)
  end

  defp write_session_attrs(socket, parsed) do
    %{
      workspace_id: socket.assigns.document.workspace_id,
      signing_key_id: socket.assigns.device_signing_key_id,
      update_data: <<>>,
      key_version: parsed.public_data["keyVersion"],
      public_data: parsed.public_data,
      owner_kind: parsed.public_data["ownerKind"],
      owner_id: parsed.public_data["ownerId"],
      authority_kind: parsed.public_data["authorityKind"],
      authority_id: parsed.public_data["authorityId"],
      authority_context_key: parsed.public_data["authorityContextKey"],
      authority_scope_id: parsed.public_data["authorityScopeId"],
      authority_permission_version: parsed.public_data["authorityPermissionVersion"],
      key_checkpoint_sequence: key_checkpoint_sequence(parsed),
      key_checkpoint_hash: key_checkpoint_hash(parsed),
      write_session_counter: parsed.public_data["writeSessionCounter"]
    }
    |> Map.put(:admission, parsed.admission)
    |> Map.put(:admission_actor, admission_actor(socket, parsed))
    |> maybe_put_share_context(socket)
  end

  defp snapshot_attrs(socket, parsed) do
    %{
      snapshot_id: parsed.public_data["snapshotId"],
      parent_snapshot_id: parent_snapshot_id(parsed.public_data["parentSnapshotId"]),
      workspace_id: socket.assigns.document.workspace_id,
      data: parsed.ciphertext_raw,
      nonce: parsed.nonce_raw,
      key_version: parsed.public_data["keyVersion"],
      hybrid_signature: parsed.signature,
      signature_verified: true,
      public_data: parsed.public_data,
      parent_proof_hash: parsed.public_data["parentProofHash"],
      parent_snapshot_update_clocks: parsed.public_data["parentSnapshotUpdateClocks"],
      created_by_signing_key_id: socket.assigns.device_signing_key_id,
      owner_kind: parsed.public_data["ownerKind"],
      owner_id: parsed.public_data["ownerId"],
      authority_kind: parsed.public_data["authorityKind"],
      authority_id: parsed.public_data["authorityId"],
      authority_context_key: parsed.public_data["authorityContextKey"],
      authority_scope_id: parsed.public_data["authorityScopeId"],
      authority_permission_version: parsed.public_data["authorityPermissionVersion"],
      key_checkpoint_sequence: key_checkpoint_sequence(parsed),
      key_checkpoint_hash: key_checkpoint_hash(parsed)
    }
    |> Map.put(:admission, parsed.admission)
    |> Map.put(:admission_actor, admission_actor(socket, parsed))
    |> maybe_put_share_context(socket)
  end

  defp admission_actor(%{assigns: %{session_kind: :share_participant}} = socket, parsed) do
    %{
      "signer_kind" => "share_participant_device",
      "share_id" => socket.assigns.current_share_id,
      "share_participant_principal_id" => socket.assigns.share_participant_principal_id,
      "share_participant_device_id" => socket.assigns.device_id,
      "signing_key_id" => socket.assigns.device_signing_key_id
    }
    |> Map.merge(checkpoint_authority(socket, parsed))
  end

  defp admission_actor(socket, parsed) do
    %{
      "signer_kind" => "device",
      "user_id" => socket.assigns.current_user_id,
      "device_id" => socket.assigns.device_id,
      "signing_key_id" => socket.assigns.device_signing_key_id
    }
    |> Map.merge(checkpoint_authority(socket, parsed))
  end

  defp checkpoint_authority(socket, parsed) do
    %{
      "key_scope_kind" => "workspace",
      "key_scope_id" => socket.assigns.document.workspace_id,
      "key_checkpoint_sequence" => key_checkpoint_sequence(parsed),
      "key_checkpoint_hash" => key_checkpoint_hash(parsed)
    }
  end

  defp parent_snapshot_id("GENESIS"), do: nil
  defp parent_snapshot_id(value), do: value

  defp key_checkpoint_sequence(%{public_data: public_data}) do
    public_data["keyCheckpointSequence"]
  end

  defp key_checkpoint_hash(%{public_data: public_data}) do
    public_data["keyCheckpointHash"]
  end

  defp maybe_put_share_context(attrs, socket) do
    if socket.assigns[:session_kind] == :share_participant do
      Map.merge(attrs, %{
        session_kind: :share_participant,
        session_id: socket.assigns.current_session.id,
        share_id: socket.assigns.current_share_id,
        grant: socket.assigns.share_participant_grant,
        principal_id: socket.assigns.share_participant_principal_id
      })
    else
      attrs
    end
  end

  defp handle_write_session_result({:ok, saved}, parsed, socket) do
    payload = %{
      admission:
        write_session_admission(
          socket.assigns.document_id,
          saved.admission_event_hash,
          current_incremental: true
        ),
      publicData: parsed.public_data
    }

    Documents.record_write_session(
      socket.assigns.document_id,
      payload,
      write_session_expires_at_ms(parsed)
    )

    broadcast_from(socket, "write-session", payload)

    {:reply, {:ok, %{writeSessionEventHash: saved.admission_event_hash}}, socket}
  end

  defp handle_write_session_result({:error, reason}, _parsed, socket) do
    {:reply, {:error, %{reason: Atom.to_string(reason)}}, socket}
  end

  defp handle_update_result({:ok, saved}, parsed, payload, socket) do
    write_session_admission =
      if Map.get(saved, :duplicate) do
        nil
      else
        record_update_write_session(saved, parsed, socket)
      end

    maybe_broadcast_update(saved, payload, socket, write_session_admission)

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
      reason: "snapshot_mismatch",
      requiresNewSnapshot: true
    })

    {:stop, :normal, socket}
  end

  defp handle_update_result({:error, reason}, parsed, _payload, socket)
       when reason in [
              :key_version_too_old,
              :clock_mismatch,
              :serialization_conflict,
              :key_rotation_required,
              :rotation_snapshot_required
            ] do
    push(socket, "update-save-failed", %{
      snapshotId: parsed.public_data["refSnapshotId"],
      clock: parsed.public_data["clock"],
      reason: Atom.to_string(reason),
      requiresNewSnapshot: false
    })

    {:stop, :normal, socket}
  end

  defp handle_update_result({:error, reason}, _parsed, _payload, socket)
       when reason in [
              :document_archived,
              :document_read_only,
              :document_write_disabled,
              :permission_denied,
              :device_revoked,
              :admission_invalid
            ] do
    {:reply, {:error, %{reason: to_string(reason)}}, socket}
  end

  defp handle_update_result({:error, reason}, _parsed, _payload, socket) do
    {:reply, {:error, %{reason: to_string(reason)}}, socket}
  end

  defp record_update_write_session(saved, parsed, socket) do
    event_hash = parsed.public_data["writeSessionEventHash"]

    if is_binary(event_hash) and event_hash == saved.admission_event_hash do
      admission =
        write_session_admission(
          socket.assigns.document_id,
          saved.admission_event_hash,
          current_incremental: true
        )

      Documents.record_write_session(
        socket.assigns.document_id,
        %{
          admission: admission,
          publicData: Map.put(parsed.public_data, "writeSessionCounter", 0)
        },
        write_session_expires_at_ms(parsed)
      )

      admission
    end
  end

  defp handle_snapshot_result({:ok, saved}, _parsed, socket) do
    Documents.set_active_snapshot(
      socket.assigns.document_id,
      saved.snapshot_id,
      %{}
    )

    saved_payload = %{
      snapshotId: saved.snapshot_id,
      latestVersion: saved.latest_version,
      proofChainHash: saved.proof_chain_hash,
      ciphertextHash: saved.ciphertext_hash,
      snapshotAdmissionEventHash: saved.snapshot_admission_event_hash
    }

    push(socket, "snapshot-saved", saved_payload)

    snapshot_payload =
      saved.snapshot_id
      |> Documents.get_snapshot()
      |> Envelope.format_snapshot(current_incremental: true)

    broadcast_from(socket, "snapshot", %{
      snapshotId: saved.snapshot_id,
      snapshot: snapshot_payload,
      proofChainHash: saved.proof_chain_hash,
      ciphertextHash: saved.ciphertext_hash,
      snapshotAdmissionEventHash: saved.snapshot_admission_event_hash
    })

    {:reply, {:ok, saved_payload}, socket}
  end

  defp handle_snapshot_result({:error, reason, recovery}, parsed, socket)
       when reason in [
              :parent_mismatch,
              :clocks_mismatch,
              :key_version_too_old,
              :rotation_snapshot_required,
              :serialization_conflict
            ] do
    failure_data =
      Envelope.build_snapshot_failure(
        recovery,
        socket.assigns.document_id,
        parsed.public_data["parentSnapshotId"],
        active_write_session_admission_opts(socket.assigns.workspace_key_directory_pin_anchor)
      )

    push(socket, "snapshot-save-failed", failure_data)
    {:reply, {:error, failure_data}, socket}
  end

  defp handle_snapshot_result({:error, reason, _recovery}, _parsed, socket)
       when reason in [
              :document_archived,
              :document_read_only,
              :document_write_disabled,
              :permission_denied,
              :device_revoked,
              :admission_invalid
            ] do
    {:reply, {:error, %{reason: to_string(reason)}}, socket}
  end

  defp handle_snapshot_result({:error, reason, _}, _parsed, socket) do
    {:reply, {:error, %{reason: to_string(reason)}}, socket}
  end

  defp maybe_broadcast_update(%{duplicate: true}, _payload, _socket, _write_session_admission),
    do: :ok

  defp maybe_broadcast_update(saved, payload, socket, write_session_admission) do
    Documents.update_clocks(
      socket.assigns.document_id,
      payload["publicData"]["authorityContextKey"],
      socket.assigns.device_signing_key_id,
      saved.clock
    )

    broadcast_envelope =
      payload
      |> Map.put("version", saved.version)
      |> Map.put(
        "admission",
        live_update_admission(socket.assigns.document_id, saved, payload, write_session_admission)
      )

    broadcast_from(socket, "update", broadcast_envelope)
  end

  defp live_update_admission(_document_id, _saved, _payload, admission) when is_map(admission) do
    admission
  end

  defp live_update_admission(document_id, saved, _payload, _admission) do
    write_session_admission(document_id, saved.admission_event_hash, current_incremental: true)
  end

  defp push_active_write_sessions(%{assigns: %{silent: true}}), do: :ok

  defp push_active_write_sessions(socket) do
    socket.assigns.document_id
    |> Documents.active_write_sessions()
    |> Enum.sort_by(&write_session_key_checkpoint_sequence/1)
    |> Enum.map(&refresh_active_write_session_admission(socket, &1))
    |> Enum.each(&push(socket, "write-session", &1))
  end

  defp refresh_active_write_session_admission(socket, payload) do
    case write_session_event_hash(payload) do
      event_hash when is_binary(event_hash) ->
        admission =
          write_session_admission(
            socket.assigns.document_id,
            event_hash,
            active_write_session_admission_opts(socket.assigns.workspace_key_directory_pin_anchor)
          )

        put_payload_admission(payload, admission)

      _ ->
        payload
    end
  end

  defp active_write_session_admission_opts(%{sequence: sequence, hash: hash}) do
    [from_checkpoint_sequence: sequence, from_checkpoint_hash: hash]
  end

  defp active_write_session_admission_opts(_anchor), do: [current_incremental: true]

  defp write_session_admission(document_id, admission_event_hash, opts) do
    Documents.document_admission_package!(
      document_id,
      "document_write_session_admitted",
      admission_event_hash,
      opts
    )
  end

  defp put_payload_admission(payload, admission) do
    if Map.has_key?(payload, "admission") do
      Map.put(payload, "admission", admission)
    else
      Map.put(payload, :admission, admission)
    end
  end

  defp write_session_key_checkpoint_sequence(payload) do
    get_in(payload, [:publicData, "keyCheckpointSequence"]) ||
      get_in(payload, ["publicData", "keyCheckpointSequence"]) ||
      0
  end

  defp write_session_event_hash(payload) do
    get_in(payload, [:publicData, "writeSessionEventHash"]) ||
      get_in(payload, ["publicData", "writeSessionEventHash"])
  end

  defp write_session_expires_at_ms(parsed) do
    parsed.admission
    |> get_in(["workspaceKeyDirectoryEvents"])
    |> List.wrap()
    |> Enum.find_value(fn
      %{"payload" => %{"event_type" => "document_write_session_admitted", "body" => body}}
      when is_map(body) ->
        body["expires_at_ms"]

      _ ->
        nil
    end)
    |> case do
      value when is_integer(value) -> value
      _ -> System.system_time(:millisecond) + 60_000
    end
  end

  defp workspace_key_directory_pin_anchor(%{
         "workspaceKeyDirectoryPinSequence" => sequence,
         "workspaceKeyDirectoryPinHash" => hash
       })
       when is_integer(sequence) and sequence > 0 and is_binary(hash) do
    %{sequence: sequence, hash: hash}
  end

  defp workspace_key_directory_pin_anchor(_params), do: nil
end
