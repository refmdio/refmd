defmodule RefMD.Documents.Admission do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Blake3, Hash, JCS, Signature}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Workspaces.WorkspaceMember

  @update_event_type "document_update_accepted"
  @snapshot_event_type "document_snapshot_accepted"

  @spec append_update!(map(), map()) :: String.t()
  def append_update!(document, attrs) do
    append!(@update_event_type, document, attrs, Map.fetch!(attrs, :update_hash))
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

  defp document_operation_event([%{"payload" => %{"body" => body} = payload} = envelope], _attrs)
       when is_map(body),
       do: {:ok, envelope, payload, body}

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
         }
       )
       when is_binary(principal_id) and is_binary(device_id) and is_binary(signing_key_id) and
              is_binary(session_id) and is_binary(share_id) do
    body = payload["body"]

    with :ok <- validate_share_participant_event_signer(signatures, actor),
         :ok <- validate_share_participant_event_body(body, document, share_id, session_id),
         {:ok, writer} <-
           Sharing.validate_share_participant_writer_admission(%{
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

  defp validate_share_participant_event_body(body, document, share_id, session_id)
       when is_map(body) do
    checks = [
      body["share_id"] == share_id,
      body["share_session_id"] == session_id,
      body["share_permission"] == "edit",
      body["share_authority_kind"] == "share_participant_device"
    ]

    with true <- Enum.all?(checks),
         true <- Sharing.can_write_document?(share_id, document.id) do
      :ok
    else
      _ -> {:error, :admission_semantic_mismatch}
    end
  end

  defp validate_share_participant_event_body(_, _, _, _),
    do: {:error, :admission_semantic_mismatch}

  defp validate_event(event_type, document, attrs, operation_hash, payload, body) do
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

  defp key_entry!(key_material, valid_from) do
    %{
      "key_id" => Signature.compute_signing_key_id!(key_material),
      "key_material" => key_material,
      "valid_from" => valid_from
    }
  end
end
