defmodule RefMD.Documents.Admission do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Blake3, Hash, JCS, Signature}
  alias RefMD.Documents.DocumentUpdate
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory.Envelope
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Workspaces.WorkspaceMember

  @update_event_type "document_write_session_admitted"
  @snapshot_event_type "document_snapshot_accepted"
  @max_write_session_lifetime_ms 60_000
  @write_session_failure_reasons [:write_session_expired, :write_session_invalid]

  @spec append_update!(map(), map()) :: String.t()
  def append_update!(document, attrs) do
    operation_hash = Map.fetch!(attrs, :update_hash)

    active_write_session_event_hash(document, attrs) ||
      append!(@update_event_type, document, attrs, operation_hash)
  end

  @spec append_write_session!(map(), map()) :: String.t()
  def append_write_session!(document, attrs) do
    attrs =
      attrs
      |> Map.put(:prewarm_write_session?, true)
      |> Map.put_new(:update_data, <<>>)

    append!(@update_event_type, document, attrs, "")
  end

  @spec append_snapshot!(map(), map()) :: String.t()
  def append_snapshot!(document, attrs) do
    append!(
      @snapshot_event_type,
      document,
      attrs,
      Blake3.hash_base64url(Map.fetch!(attrs, :data))
    )
  end

  defp append!(event_type, document, attrs, operation_hash) do
    append_workspace_admission!(event_type, document, attrs, operation_hash)
  rescue
    _exception in [ArgumentError, KeyError] ->
      Repo.rollback(:admission_invalid)
  end

  defp append_workspace_admission!(event_type, document, attrs, operation_hash) do
    with {:ok, events, checkpoint} <- admission_artifacts(attrs),
         {:ok, _event_envelope, event_payload, body} <-
           document_operation_event(events, attrs),
         {:ok, authorized_share_participant_keys} <-
           validate_share_participant_writer_admission(events, document, attrs),
         :ok <- validate_event(event_type, document, attrs, operation_hash, event_payload, body),
         :ok <- ensure_signed_events(events) do
      maybe_append_workspace_event!(
        document.workspace_id,
        event_payload,
        events,
        checkpoint,
        attrs,
        authorized_share_participant_keys
      )

      event_hash(event_payload)
    else
      {:error, reason} when reason in @write_session_failure_reasons ->
        Repo.rollback(reason)

      _error ->
        Repo.rollback(:admission_invalid)
    end
  end

  defp maybe_append_workspace_event!(
         workspace_id,
         event_payload,
         events,
         checkpoint,
         attrs,
         authorized_share_participant_keys
       ) do
    if existing_event?(workspace_id, event_payload) do
      :ok
    else
      validate_current_head!(workspace_id, events)

      Encryption.append_workspace_key_directory!(
        workspace_id,
        events,
        checkpoint,
        checkpoint_signer_kind: expected_checkpoint_signer_kind(attrs),
        authorized_share_participant_keys: authorized_share_participant_keys
      )

      :ok
    end
  end

  defp admission_artifacts(%{
         admission: %{
           "workspaceKeyDirectoryEvents" => events,
           "workspaceKeyDirectoryCheckpoint" => checkpoint
         }
       })
       when is_list(events) and is_map(checkpoint),
       do: {:ok, events, checkpoint}

  defp admission_artifacts(_), do: {:error, :admission_required}

  defp document_operation_event([envelope], _attrs) do
    payload = Envelope.payload!(envelope, :event)
    {:ok, envelope, payload, payload["body"]}
  end

  defp document_operation_event(_events, _attrs), do: {:error, :admission_event_invalid}

  defp validate_share_participant_writer_admission(
         [_single_event],
         _document,
         %{admission_actor: %{"signer_kind" => signer_kind}}
       )
       when signer_kind == "device",
       do: {:ok, %{}}

  defp validate_share_participant_writer_admission(
         [%{"payload" => payload, "signatures" => signatures}],
         document,
         %{
           admission_actor:
             %{
               "signer_kind" => "share_participant_device",
               "share_id" => share_id,
               "share_participant_principal_id" => principal_id,
               "share_participant_device_id" => device_id,
               "signing_key_id" => signing_key_id
             } = actor,
           session_kind: :share_participant,
           session_id: session_id,
           share_id: share_id,
           grant: "edit",
           principal_id: principal_id
         } = attrs
       )
       when is_binary(principal_id) and is_binary(device_id) and is_binary(signing_key_id) and
              is_binary(session_id) and is_binary(share_id) do
    body = payload["body"]

    with :ok <- validate_share_participant_event_signer(signatures, actor),
         :ok <- validate_share_participant_event_body(body, document, share_id, session_id, attrs),
         {:ok, writer} <-
           share_participant_writer_admission(attrs, %{
             share_id: share_id,
             principal_id: principal_id,
             device_id: device_id,
             session_id: session_id,
             signing_key_id: signing_key_id,
             document_id: document.id
           }) do
      entry =
        key_entry!(writer.hybrid_signing_public_key_material, %{
          "scope_kind" => "workspace",
          "scope_id" => document.workspace_id,
          "event_sequence" => payload["sequence"],
          "event_hash" => event_hash(payload)
        })

      {:ok, %{signing_key_id => entry}}
    else
      _ -> {:error, :admission_semantic_mismatch}
    end
  end

  defp validate_share_participant_writer_admission(_events, _document, _attrs),
    do: {:error, :admission_semantic_mismatch}

  defp share_participant_writer_admission(
         %{share_participant_writer_context: %{hybrid_signing_public_key_material: material}},
         _params
       )
       when is_map(material),
       do: {:ok, %{hybrid_signing_public_key_material: material}}

  defp share_participant_writer_admission(_attrs, params),
    do: Sharing.validate_share_participant_writer_admission(params)

  defp validate_share_participant_event_signer(signatures, expected_actor)
       when is_list(signatures) do
    if Enum.any?(signatures, fn
         %{"signer" => signer} -> signer == expected_actor
         _ -> false
       end) do
      :ok
    else
      {:error, :admission_semantic_mismatch}
    end
  end

  defp validate_share_participant_event_signer(_signatures, _expected_actor),
    do: {:error, :admission_semantic_mismatch}

  defp validate_share_participant_event_body(body, document, share_id, session_id, attrs)
       when is_map(body) do
    checks = [
      body["share_id"] == share_id,
      body["share_session_id"] == session_id,
      body["share_permission"] == "edit",
      body["share_authority_kind"] == "share_participant_device"
    ]

    with true <- Enum.all?(checks),
         true <- share_participant_write_authorized?(attrs, share_id, document.id) do
      :ok
    else
      _ -> {:error, :admission_semantic_mismatch}
    end
  end

  defp validate_share_participant_event_body(_, _, _, _, _),
    do: {:error, :admission_semantic_mismatch}

  defp share_participant_write_authorized?(
         %{share_participant_writer_context: %{hybrid_signing_public_key_material: material}},
         _share_id,
         _document_id
       )
       when is_map(material),
       do: true

  defp share_participant_write_authorized?(_attrs, share_id, document_id),
    do: Sharing.can_write_document?(share_id, document_id)

  defp validate_event(event_type, document, attrs, operation_hash, payload, body) do
    if event_type == @update_event_type do
      validate_write_session_event(event_type, document, attrs, payload, body)
    else
      validate_operation_event(event_type, document, attrs, operation_hash, payload, body)
    end
  end

  defp validate_operation_event(event_type, document, attrs, operation_hash, payload, body) do
    expected_actor = Map.fetch!(attrs, :admission_actor)

    signature_hash =
      attrs
      |> Map.fetch!(:hybrid_signature)
      |> JCS.canonical_bytes!()
      |> Hash.blake3_base64url()

    actor_hash = Hash.blake3_base64url(JCS.canonical_bytes!(expected_actor))

    checks = [
      scope_kind: payload["scope_kind"] == "workspace",
      scope_id: payload["scope_id"] == document.workspace_id,
      event_type: payload["event_type"] == event_type,
      actor: payload["actor"] == expected_actor,
      previous_event_hash:
        payload["previous_event_hash"] == body["previous_workspace_event_hash"],
      previous_event_sequence:
        body["previous_workspace_event_sequence"] == payload["sequence"] - 1,
      body_event_type: body["event_type"] == event_type,
      workspace_id: body["workspace_id"] == document.workspace_id,
      document_id: body["document_id"] == document.id,
      document_permission_proof_hash:
        body["document_permission_proof_hash"] == document_permission_proof_hash(document, attrs),
      authority_scope:
        Map.fetch!(attrs, :authority_scope_id) == expected_authority_scope_id(document, attrs),
      authority_permission_version:
        Map.fetch!(attrs, :authority_permission_version) ==
          expected_authority_permission_version(document, attrs),
      operation_hash: body["operation_hash"] == operation_hash,
      operation_signature_hash: body["operation_signature_hash"] == signature_hash,
      actor_hash: body["actor_hash"] == actor_hash,
      dek_version: body["dek_version"] == attrs.key_version,
      min_dek_version: body["min_dek_version"] == document.min_dek_version
    ]

    if Enum.all?(checks, fn {_label, ok?} -> ok? end) do
      :ok
    else
      {:error, :admission_semantic_mismatch}
    end
  end

  defp validate_write_session_event(event_type, document, attrs, payload, body) do
    context = write_session_validation_context(document, attrs, payload, body)

    case write_session_time_window_result(context.time_window_status) do
      :ok ->
        if write_session_event_valid?(event_type, document, attrs, payload, body, context),
          do: :ok,
          else: {:error, :write_session_invalid}

      error ->
        error
    end
  end

  defp write_session_validation_context(document, attrs, payload, body) do
    session_hash = Map.get(attrs, :cached_write_session_event_hash) || event_hash(payload)

    {session_update_count, session_ciphertext_bytes} =
      write_session_usage_with_current(document.id, session_hash, Map.fetch!(attrs, :update_data))

    %{
      actor_hash:
        Hash.blake3_base64url(JCS.canonical_bytes!(Map.fetch!(attrs, :admission_actor))),
      expected_actor: Map.fetch!(attrs, :admission_actor),
      prewarm?: Map.get(attrs, :prewarm_write_session?) == true,
      session_ciphertext_bytes: session_ciphertext_bytes,
      session_hash: session_hash,
      session_update_count: session_update_count,
      time_window_status:
        write_session_time_window_status(body, System.system_time(:millisecond)),
      write_session_counter: Map.fetch!(attrs, :write_session_counter)
    }
  end

  defp write_session_time_window_result(:expired), do: {:error, :write_session_expired}
  defp write_session_time_window_result(:invalid), do: {:error, :write_session_invalid}
  defp write_session_time_window_result(_valid), do: :ok

  defp write_session_event_valid?(event_type, document, attrs, payload, body, context) do
    [
      write_session_payload_valid?(event_type, document, attrs, payload, body, context),
      write_session_authority_valid?(document, attrs, body),
      write_session_public_data_valid?(attrs, body, context),
      write_session_budget_valid?(attrs, body, context),
      write_session_not_invalidated?(document, attrs, payload, context.session_hash)
    ]
    |> Enum.all?()
  end

  defp write_session_payload_valid?(event_type, document, attrs, payload, body, context) do
    [
      write_session_payload_scope_valid?(event_type, document, payload, context),
      write_session_payload_previous_valid?(payload, body),
      write_session_body_target_valid?(event_type, document, body),
      write_session_body_permission_valid?(document, attrs, body, context)
    ]
    |> Enum.all?()
  end

  defp write_session_payload_scope_valid?(event_type, document, payload, context) do
    payload["scope_kind"] == "workspace" and
      payload["scope_id"] == document.workspace_id and
      payload["event_type"] == event_type and
      payload["actor"] == context.expected_actor
  end

  defp write_session_payload_previous_valid?(payload, body) do
    payload["previous_event_hash"] == body["previous_workspace_event_hash"] and
      body["previous_workspace_event_sequence"] == payload["sequence"] - 1
  end

  defp write_session_body_target_valid?(event_type, document, body) do
    body["event_type"] == event_type and
      body["workspace_id"] == document.workspace_id and
      body["document_id"] == document.id
  end

  defp write_session_body_permission_valid?(document, attrs, body, context) do
    body["actor_hash"] == context.actor_hash and
      body["min_dek_version"] == document.min_dek_version and
      body["document_permission_proof_hash"] == document_permission_proof_hash(document, attrs)
  end

  defp write_session_authority_valid?(document, attrs, body) do
    body["authority_kind"] == Map.fetch!(attrs, :authority_kind) and
      body["authority_scope_id"] == Map.fetch!(attrs, :authority_scope_id) and
      Map.fetch!(attrs, :authority_scope_id) == expected_authority_scope_id(document, attrs) and
      Map.fetch!(attrs, :authority_permission_version) ==
        expected_authority_permission_version(document, attrs)
  end

  defp write_session_public_data_valid?(attrs, body, context) do
    attrs.public_data["minDekVersion"] == body["min_dek_version"] and
      attrs.public_data["writeSessionId"] == body["session_id"] and
      attrs.public_data["writeSessionEventHash"] == context.session_hash and
      valid_write_session_counter?(body, context) and
      write_session_counter_available?(attrs, context)
  end

  defp write_session_budget_valid?(_attrs, body, context) do
    context.session_update_count <= body["max_update_count"] and
      is_integer(body["max_ciphertext_bytes"]) and
      context.session_ciphertext_bytes <= body["max_ciphertext_bytes"]
  end

  defp valid_write_session_counter?(_body, %{prewarm?: true, write_session_counter: 0}), do: true

  defp valid_write_session_counter?(body, context) do
    is_integer(context.write_session_counter) and
      context.write_session_counter > 0 and
      context.write_session_counter <= body["max_update_count"]
  end

  defp write_session_counter_available?(_attrs, %{prewarm?: true}), do: true

  defp write_session_counter_available?(attrs, context) do
    write_session_counter_unused?(
      context.session_hash,
      Map.fetch!(attrs, :signing_key_id),
      context.write_session_counter
    )
  end

  defp write_session_not_invalidated?(document, attrs, payload, session_hash) do
    case write_session_replay_events(document.workspace_id, payload, session_hash) do
      {:ok, replay_events} ->
        not Enum.any?(replay_events, fn event ->
          write_session_invalidating_event?(event, document, attrs, payload)
        end)

      _ ->
        false
    end
  end

  defp write_session_replay_events(workspace_id, payload, session_hash) do
    session_sequence = payload["sequence"]
    pin = Encryption.current_workspace_key_directory_pin(workspace_id)

    cond do
      is_nil(pin) or not is_integer(session_sequence) ->
        {:error, :write_session_invalid}

      pin.event_head_sequence == session_sequence - 1 and
          pin.event_head_hash == payload["previous_event_hash"] ->
        {:ok, []}

      pin.event_head_sequence < session_sequence ->
        {:error, :write_session_invalid}

      true ->
        case Encryption.workspace_key_directory_event_by_hash(workspace_id, session_hash) do
          %{event_type: @update_event_type, sequence: ^session_sequence} ->
            {:ok,
             Encryption.workspace_key_directory_events_after_until(
               workspace_id,
               session_sequence,
               pin.event_head_sequence
             )}

          _ ->
            {:error, :write_session_invalid}
        end
    end
  end

  defp write_session_invalidating_event?(
         %{event_type: "signing_key_revoked", payload: %{"body" => body}},
         _document,
         attrs,
         _session_payload
       )
       when is_map(body) do
    body["key_id"] == Map.fetch!(attrs, :signing_key_id)
  end

  defp write_session_invalidating_event?(
         %{event_type: "member_removed", payload: %{"body" => body}},
         document,
         attrs,
         session_payload
       )
       when is_map(body) do
    actor = Map.get(session_payload, "actor", %{})

    document_session_owner?(attrs, actor) and body["user_id"] == actor["user_id"] and
      body["workspace_id"] == document.workspace_id
  end

  defp write_session_invalidating_event?(
         %{event_type: "member_role_changed", payload: %{"body" => body}},
         document,
         attrs,
         session_payload
       )
       when is_map(body) do
    actor = Map.get(session_payload, "actor", %{})

    document_session_owner?(attrs, actor) and body["user_id"] == actor["user_id"] and
      body["workspace_id"] == document.workspace_id and
      not base_role_can_write_document?(body["base_role"])
  end

  defp write_session_invalidating_event?(
         %{event_type: "share_revoked", payload: %{"body" => body}},
         _document,
         attrs,
         session_payload
       )
       when is_map(body) do
    actor = Map.get(session_payload, "actor", %{})
    share_session_owner?(attrs, actor) and body["share_id"] == actor["share_id"]
  end

  defp write_session_invalidating_event?(
         %{event_type: "share_key_scope_removed", payload: %{"body" => body}},
         document,
         attrs,
         session_payload
       )
       when is_map(body) do
    actor = Map.get(session_payload, "actor", %{})

    share_session_owner?(attrs, actor) and body["share_id"] == actor["share_id"] and
      body["workspace_id"] == document.workspace_id and
      share_scope_removal_targets_document?(body, document)
  end

  defp write_session_invalidating_event?(
         %{event_type: "guest_grant_revoked", payload: %{"body" => body}},
         document,
         attrs,
         session_payload
       )
       when is_map(body) do
    actor = Map.get(session_payload, "actor", %{})

    share_session_owner?(attrs, actor) and
      body["guest_user_id"] == actor["share_participant_principal_id"] and
      guest_grant_revocation_targets_session?(body, document, actor)
  end

  defp write_session_invalidating_event?(
         %{event_type: "guest_device_revoked", payload: %{"body" => body}},
         _document,
         attrs,
         session_payload
       )
       when is_map(body) do
    actor = Map.get(session_payload, "actor", %{})

    share_session_owner?(attrs, actor) and
      body["guest_user_id"] == actor["share_participant_principal_id"] and
      guest_device_revocation_targets_actor?(body, actor)
  end

  defp write_session_invalidating_event?(
         %{event_type: event_type, payload: %{"body" => body}},
         document,
         attrs,
         _session_payload
       )
       when event_type in ["rotation_started", "rotation_completed"] and is_map(body) do
    dek_floor_invalidates_session?(body, document.id, Map.fetch!(attrs, :key_version))
  end

  defp write_session_invalidating_event?(
         %{event_type: "document_write_state_changed", payload: %{"body" => body}},
         document,
         _attrs,
         _session_payload
       )
       when is_map(body) do
    body["workspace_id"] == document.workspace_id and body["document_id"] == document.id and
      body["write_state"] in ["archived", "read_only", "write_disabled"]
  end

  defp write_session_invalidating_event?(_event, _document, _attrs, _session_payload),
    do: false

  defp share_scope_removal_targets_document?(
         %{"scope_kind" => "document", "scope_id" => scope_id},
         document
       ),
       do: scope_id == document.id

  defp share_scope_removal_targets_document?(
         %{"scope_kind" => "folder", "scope_id" => scope_id},
         document
       )
       when is_binary(scope_id) do
    RefMD.Sharing.Access.descendant_of?(document.id, scope_id)
  rescue
    _ -> false
  end

  defp share_scope_removal_targets_document?(_body, _document), do: false

  defp guest_grant_revocation_targets_session?(%{"scope_kind" => "workspace"}, _document, _actor),
    do: true

  defp guest_grant_revocation_targets_session?(
         %{"scope_kind" => "share", "scope_id" => scope_id},
         _document,
         actor
       ),
       do: scope_id == actor["share_id"]

  defp guest_grant_revocation_targets_session?(body, document, _actor),
    do: share_scope_removal_targets_document?(body, document)

  defp guest_device_revocation_targets_actor?(body, actor) do
    body["guest_device_id"] == actor["share_participant_device_id"] or
      body["guest_signing_key_id"] == actor["signing_key_id"]
  end

  defp document_session_owner?(attrs, actor),
    do: attrs.public_data["ownerKind"] == "device" and is_map(actor)

  defp share_session_owner?(attrs, actor),
    do: attrs.public_data["ownerKind"] == "share_participant_device" and is_map(actor)

  if Mix.env() == :test do
    @doc false
    @spec __test_write_session_invalidating_event?(map(), map(), map(), map()) :: boolean()
    def __test_write_session_invalidating_event?(event, document, attrs, session_payload),
      do: write_session_invalidating_event?(event, document, attrs, session_payload)
  end

  defp base_role_can_write_document?(role),
    do: role in ["owner", "admin", "editor", "guest"]

  defp dek_floor_invalidates_session?(body, document_id, key_version) do
    body["rotation_kind"] == "dek" and body["scope_kind"] == "document" and
      body["scope_id"] == document_id and is_integer(body["new_key_version"]) and
      body["new_key_version"] > key_version
  end

  defp write_session_time_window_status(body, now_ms) do
    issued_at_ms = body["issued_at_ms"]
    expires_at_ms = body["expires_at_ms"]

    cond do
      not is_integer(issued_at_ms) or not is_integer(expires_at_ms) ->
        :invalid

      expires_at_ms < now_ms ->
        :expired

      issued_at_ms > now_ms or expires_at_ms <= issued_at_ms or
        expires_at_ms > now_ms + @max_write_session_lifetime_ms or
          expires_at_ms - issued_at_ms > @max_write_session_lifetime_ms ->
        :invalid

      true ->
        :ok
    end
  end

  defp write_session_usage_with_current(document_id, admission_event_hash, update_data) do
    {count, bytes} =
      from(u in DocumentUpdate,
        where: u.document_id == ^document_id and u.admission_event_hash == ^admission_event_hash,
        select: {count(u.id), coalesce(sum(fragment("octet_length(?)", u.update_data)), 0)}
      )
      |> Repo.one()

    {count + 1, bytes + byte_size(update_data)}
  end

  defp write_session_counter_unused?(admission_event_hash, signing_key_id, counter) do
    not Repo.exists?(
      from(u in DocumentUpdate,
        where:
          u.admission_event_hash == ^admission_event_hash and
            u.signing_key_id == ^signing_key_id and
            u.write_session_counter == ^counter
      )
    )
  end

  defp document_permission_proof_hash(document, attrs) do
    %{
      "protocol" => "refmd.document-permission-proof",
      "version" => 1,
      "workspace_id" => document.workspace_id,
      "document_id" => document.id,
      "authority_kind" => Map.fetch!(attrs, :authority_kind),
      "authority_id" => Map.fetch!(attrs, :authority_id),
      "authority_context_key" => Map.fetch!(attrs, :authority_context_key),
      "authority_scope_id" => Map.fetch!(attrs, :authority_scope_id),
      "authority_permission_version" => Map.fetch!(attrs, :authority_permission_version),
      "permission" => "edit"
    }
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  defp expected_authority_scope_id(document, %{authority_kind: "workspace_device"}),
    do: document.workspace_id

  defp expected_authority_scope_id(
         _document,
         %{authority_kind: "share_participant_device"} = attrs
       ),
       do: Map.fetch!(attrs, :authority_id)

  defp expected_authority_permission_version(
         document,
         %{authority_kind: "workspace_device", admission_actor: %{"user_id" => user_id}}
       ) do
    from(m in WorkspaceMember,
      where: m.workspace_id == ^document.workspace_id and m.user_id == ^user_id,
      select: m.permission_version,
      limit: 1
    )
    |> Repo.one()
    |> case do
      version when is_integer(version) and version > 0 -> version
      _ -> 1
    end
  end

  defp expected_authority_permission_version(
         _document,
         %{
           authority_kind: "share_participant_device",
           authority_id: share_id
         }
       ) do
    Sharing.get_share_permission_version(share_id)
  end

  defp validate_current_head!(workspace_id, [%{"payload" => payload} | _events]) do
    pin = Encryption.current_workspace_key_directory_pin(workspace_id)

    if is_nil(pin), do: raise(ArgumentError, "key_directory_checkpoint_required")

    if payload["sequence"] != pin.event_head_sequence + 1 or
         payload["previous_event_hash"] != pin.event_head_hash do
      raise ArgumentError, "admission_workspace_head_stale"
    end
  end

  defp validate_current_head!(_workspace_id, _events),
    do: raise(ArgumentError, "admission_workspace_head_stale")

  defp ensure_signed_event_envelope(%{"signatures" => signatures})
       when is_list(signatures) and signatures != [],
       do: :ok

  defp ensure_signed_event_envelope(_), do: {:error, :admission_unsigned}

  defp ensure_signed_events(events) do
    if Enum.all?(events, &match?(:ok, ensure_signed_event_envelope(&1))),
      do: :ok,
      else: {:error, :admission_unsigned}
  end

  defp expected_checkpoint_signer_kind(%{
         admission_actor: %{"signer_kind" => "share_participant_device"}
       }),
       do: "share_participant_device"

  defp expected_checkpoint_signer_kind(_attrs), do: "device"

  defp existing_event?(workspace_id, payload) do
    hash = event_hash(payload)

    Encryption.workspace_key_directory_event_type_by_hash(workspace_id, hash) ==
      payload["event_type"]
  end

  defp event_hash(payload), do: Hash.blake3_base64url(JCS.canonical_bytes!(payload))

  defp active_write_session_event_hash(document, attrs) do
    expected_hash = get_in(Map.fetch!(attrs, :public_data), ["writeSessionEventHash"])

    with true <- is_binary(expected_hash),
         cached_payload when is_map(cached_payload) <-
           active_write_session_payload(document.id, expected_hash),
         cached_admission when is_map(cached_admission) <-
           write_session_payload_admission(cached_payload),
         {:ok, cached_events, _cached_checkpoint} <-
           admission_artifacts(%{admission: cached_admission}),
         :ok <- ensure_signed_events(cached_events),
         {:ok, _cached_envelope, cached_event_payload, cached_body} <-
           document_operation_event(cached_events, attrs),
         ^expected_hash <- event_hash(cached_event_payload),
         :ok <-
           validate_event(
             @update_event_type,
             document,
             Map.put(attrs, :cached_write_session_event_hash, expected_hash),
             "",
             cached_event_payload,
             cached_body
           ) do
      expected_hash
    else
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp active_write_session_payload(document_id, event_hash) do
    case Registry.lookup(RefMD.Documents.Runtime.Registry, document_id) do
      [{_pid, _value}] ->
        document_id
        |> RefMD.Documents.Runtime.Server.active_write_sessions()
        |> Enum.find(&(write_session_payload_event_hash(&1) == event_hash))

      [] ->
        nil
    end
  rescue
    _ -> nil
  end

  defp write_session_payload_admission(payload) do
    Map.get(payload, :admission) || Map.get(payload, "admission")
  end

  defp write_session_payload_event_hash(payload) do
    get_in(payload, [:publicData, "writeSessionEventHash"]) ||
      get_in(payload, ["publicData", "writeSessionEventHash"])
  end

  defp key_entry!(key_material, valid_from) do
    %{
      "key_id" => Signature.compute_signing_key_id!(key_material),
      "key_material" => key_material,
      "valid_from" => valid_from
    }
  end
end
