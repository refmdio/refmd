defmodule RefMD.Encryption.Workspaces do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Encoding, Hash, JCS}
  alias RefMD.Devices
  alias RefMD.Encryption.{KeyDirectory, WorkspaceEncryptedKey}
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo

  defp create(attrs) do
    sender_device_id = dual_key_get(attrs, :sender_device_id)

    if sender_device_id != nil and not active_device?(sender_device_id) do
      {:error, :invalid_sender_device}
    else
      %WorkspaceEncryptedKey{created_at: DateTime.utc_now()}
      |> WorkspaceEncryptedKey.changeset(attrs)
      |> Repo.insert()
    end
  end

  def create_with_key_directory(attrs, workspace_events, workspace_checkpoint)
      when is_list(workspace_events) and is_map(workspace_checkpoint) do
    Repo.transaction(fn ->
      validate_device_key_wrap_for_write!(attrs, workspace_events, workspace_checkpoint)

      KeyDirectory.append_signed_scope!(
        "workspace",
        attrs.workspace_id,
        workspace_events,
        workspace_checkpoint,
        checkpoint_signer_kind: "device"
      )

      assert_operation_checkpoint_matches_current_pin!("workspace", attrs.workspace_id, attrs)

      case create(attrs) do
        {:ok, key} -> key
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, key} -> {:ok, key}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def create_with_key_directory(_, _, _), do: {:error, :missing_key_directory}

  def create_from_client_wrap(
        container,
        metadata,
        validation_context,
        workspace_events,
        workspace_checkpoint
      )
      when is_map(container) and is_map(metadata) and is_map(validation_context) do
    attrs = build_device_key_wrap_attrs!(container, metadata)

    with :ok <-
           validate_device_key_wrap(
             attrs,
             validation_context,
             Map.fetch!(validation_context, :sender_device),
             Map.fetch!(validation_context, :target_device),
             workspace_events
           ) do
      create_with_key_directory(attrs, workspace_events, workspace_checkpoint)
    end
  rescue
    _ -> {:error, :invalid_workspace_device_kek_wrap}
  end

  def validate_share_link_secret_backup_wrap(wrap, context)
      when is_map(wrap) and is_map(context) do
    signed_attrs = SignedPQ.attrs_from_params!(wrap)
    resource = Map.fetch!(wrap, "resource")
    recipient = Map.fetch!(wrap, "recipient")
    sender = Map.fetch!(wrap, "sender")
    event_scope = Map.fetch!(wrap, "event_scope")
    expected_recipient = Map.fetch!(context, :expected_recipient)
    sender_device = Map.fetch!(context, :sender_device)

    :ok = validate_share_backup_resource!(resource, context)
    :ok = validate_share_backup_recipient!(resource, recipient, expected_recipient)
    :ok = validate_share_backup_key_ids!(signed_attrs, expected_recipient, sender_device)

    :ok =
      validate_share_backup_signed_context!(
        signed_attrs,
        resource,
        recipient,
        sender,
        event_scope,
        context
      )

    :ok = validate_share_backup_operation_checkpoint!(signed_attrs, context)

    case SignedPQ.verify_signature(signed_attrs, sender_device.hybrid_signing_public_key_material) do
      :ok -> :ok
      {:error, _reason} -> raise ArgumentError, "share_link_secret_backup_signature_invalid"
    end
  rescue
    _ -> {:error, :invalid_share_link_secret_backup_wrap}
  end

  defp validate_device_key_wrap_for_write!(attrs, workspace_events, workspace_checkpoint) do
    sender_device = active_device_record!(fetch_attr!(attrs, :sender_device_id))
    target_device = active_device_record!(fetch_attr!(attrs, :device_id))

    :ok =
      validate_device_key_wrap(
        attrs,
        %{
          workspace_id: fetch_attr!(attrs, :workspace_id),
          sender_user_id: sender_device.user_id,
          target_user_id: fetch_attr!(attrs, :user_id),
          workspace_checkpoint: workspace_checkpoint
        },
        sender_device,
        target_device,
        workspace_events
      )
  rescue
    _ -> Repo.rollback(:invalid_workspace_device_kek_wrap)
  end

  def build_device_key_wrap_attrs!(container, metadata) do
    container
    |> SignedPQ.attrs_from_container_params!()
    |> Map.merge(metadata)
  end

  def validate_device_key_wrap(attrs, context, sender_device, target_device, key_directory_events) do
    key_checkpoint = key_checkpoint_context!(attrs, context)

    case SignedPQ.validate_workspace_device_kek(attrs, %{
           workspace_id: Map.fetch!(context, :workspace_id),
           sender_user_id: Map.fetch!(context, :sender_user_id),
           target_user_id: Map.fetch!(context, :target_user_id),
           device_id: attrs.device_id,
           key_version: attrs.key_version,
           sender_device_id: sender_device.id,
           operation_checkpoint_sequence: attrs.operation_checkpoint_sequence,
           operation_checkpoint_hash: Encoding.encode_base64url(attrs.operation_checkpoint_hash),
           key_checkpoint_sequence: key_checkpoint.sequence,
           key_checkpoint_hash: key_checkpoint.hash,
           key_directory_events: key_directory_events
         }) do
      :ok ->
        cond do
          encode_signing_key_id(attrs.sender_signing_key_id) != sender_device.signing_key_id ->
            {:error, :invalid_workspace_device_kek_wrap}

          encode_signing_key_id(attrs.recipient_key_id) != target_device.encryption_key_id ->
            {:error, :invalid_workspace_device_kek_wrap}

          true ->
            verify_device_key_wrap_signature(attrs, sender_device)
        end

      {:error, _reason} ->
        {:error, :invalid_workspace_device_kek_wrap}
    end
  rescue
    _ -> {:error, :invalid_workspace_device_kek_wrap}
  end

  defp key_checkpoint_context!(attrs, context) do
    checkpoint = Map.fetch!(context, :workspace_checkpoint)
    payload = Map.fetch!(checkpoint, "payload")
    previous_checkpoint_hash = Map.fetch!(payload, "previous_checkpoint_hash")
    sequence = attrs.operation_checkpoint_sequence - 1

    if sequence < 1 or not is_binary(previous_checkpoint_hash) do
      raise ArgumentError, "key_checkpoint_invalid"
    end

    %{sequence: sequence, hash: previous_checkpoint_hash}
  end

  defp validate_share_backup_operation_checkpoint!(signed_attrs, context) do
    checkpoint_payload = Map.fetch!(context, :key_directory_checkpoint_payload)

    expected_hash =
      checkpoint_payload
      |> Map.put("covered_event_head", %{
        "head_sequence" => signed_attrs.operation_checkpoint_covered_head_sequence,
        "head_hash" => encode_wrap_binary(signed_attrs.operation_checkpoint_covered_head_hash)
      })
      |> JCS.canonical_bytes!()
      |> Hash.blake3_base64url()

    if checkpoint_payload["sequence"] == signed_attrs.operation_checkpoint_sequence and
         expected_hash == encode_wrap_binary(signed_attrs.operation_checkpoint_hash),
       do: :ok,
       else: raise(ArgumentError, "share_link_secret_backup_checkpoint_invalid")
  end

  defp validate_share_backup_resource!(resource, context) when is_map(resource) do
    expected_resource = Map.fetch!(context, :expected_resource)

    if Map.take(resource, Map.keys(expected_resource)) == expected_resource and
         is_binary(resource["key_checkpoint_hash"]) and resource["key_checkpoint_hash"] != "",
       do: :ok,
       else: raise(ArgumentError, "share_link_secret_backup_resource_invalid")
  end

  defp validate_share_backup_resource!(_, _),
    do: raise(ArgumentError, "share_link_secret_backup_resource_invalid")

  defp validate_share_backup_recipient!(resource, recipient, expected_recipient)
       when is_map(recipient) do
    expected = %{
      resource_user_id: expected_recipient.user_id,
      resource_device_id: expected_recipient.device_id,
      resource_encryption_key_id: expected_recipient.encryption_key_id,
      recipient_kind: "device",
      recipient_user_id: expected_recipient.user_id,
      recipient_device_id: expected_recipient.device_id,
      recipient_encryption_key_id: expected_recipient.encryption_key_id
    }

    actual = %{
      resource_user_id: resource["recipient_user_id"],
      resource_device_id: resource["recipient_device_id"],
      resource_encryption_key_id: resource["recipient_encryption_key_id"],
      recipient_kind: recipient["recipient_kind"],
      recipient_user_id: recipient["user_id"],
      recipient_device_id: recipient["device_id"],
      recipient_encryption_key_id: recipient["encryption_key_id"]
    }

    if actual == expected,
      do: :ok,
      else: raise(ArgumentError, "share_link_secret_backup_recipient_invalid")
  end

  defp validate_share_backup_recipient!(_, _, _),
    do: raise(ArgumentError, "share_link_secret_backup_recipient_invalid")

  defp validate_share_backup_key_ids!(signed_attrs, expected_recipient, sender_device) do
    if encode_wrap_binary(signed_attrs.recipient_key_id) == expected_recipient.encryption_key_id and
         encode_wrap_binary(signed_attrs.sender_signing_key_id) == sender_device.signing_key_id,
       do: :ok,
       else: raise(ArgumentError, "share_link_secret_backup_key_id_invalid")
  end

  defp validate_share_backup_signed_context!(
         signed_attrs,
         resource,
         recipient,
         sender,
         event_scope,
         context
       ) do
    case SignedPQ.validate_share_link_secret_backup(signed_attrs, %{
           resource: resource,
           recipient: recipient,
           sender: sender,
           event_scope: event_scope,
           recipient_key_id: recipient["encryption_key_id"],
           sender_signing_key_id: sender["signing_key_id"],
           key_directory_events: Map.fetch!(context, :key_directory_events)
         }) do
      :ok -> :ok
      {:error, _reason} -> raise(ArgumentError, "share_link_secret_backup_context_invalid")
    end
  end

  def operation_checkpoint_envelope(%{operation_checkpoint_sequence: sequence} = key)
      when is_integer(sequence) do
    expected_hash = Base.url_encode64(key.operation_checkpoint_hash, padding: false)

    case KeyDirectory.checkpoints_between(
           "workspace",
           key.workspace_id,
           sequence,
           sequence
         ) do
      [%{checkpoint_hash: ^expected_hash, payload: payload, signatures: signatures}] ->
        %{payload: payload, signatures: signatures}

      _ ->
        nil
    end
  end

  def operation_checkpoint_envelope(_), do: nil

  def operation_checkpoint_ancestry(%{operation_checkpoint_sequence: sequence} = key)
      when is_integer(sequence) and sequence > 0 do
    current = KeyDirectory.current_checkpoint("workspace", key.workspace_id)

    if current do
      KeyDirectory.checkpoints_between("workspace", key.workspace_id, 1, current.sequence)
      |> Enum.reject(
        &(&1.sequence == sequence && &1.checkpoint_hash == key.operation_checkpoint_hash)
      )
      |> Enum.map(&serialize_key_directory_checkpoint/1)
    else
      []
    end
  end

  def operation_checkpoint_ancestry(_), do: []

  def operation_event_ancestry(%{operation_checkpoint_covered_head_sequence: sequence} = key)
      when is_integer(sequence) and sequence > 0 do
    KeyDirectory.events_after_until("workspace", key.workspace_id, 0, sequence)
    |> Enum.map(&serialize_key_directory_event/1)
  end

  def operation_event_ancestry(_), do: []

  def assert_operation_checkpoint_matches_current_pin!(scope_kind, scope_id, attrs) do
    pin = KeyDirectory.current_pin(scope_kind, scope_id)
    if is_nil(pin), do: raise(ArgumentError, "key_directory_checkpoint_required")

    if operation_checkpoint_sequence(attrs) != pin.checkpoint_sequence or
         operation_checkpoint_hash(attrs) != pin.checkpoint_hash or
         operation_checkpoint_covered_head_sequence(attrs) != pin.event_head_sequence or
         operation_checkpoint_covered_head_hash(attrs) != pin.event_head_hash do
      raise ArgumentError, "operation_checkpoint_mismatch"
    end

    :ok
  end

  def operation_checkpoint_sequence(attrs),
    do: dual_key_get(attrs, :operation_checkpoint_sequence)

  def operation_checkpoint_hash(attrs) do
    case dual_key_get(attrs, :operation_checkpoint_hash) do
      value when is_binary(value) -> Encoding.encode_base64url(value)
      _ -> nil
    end
  end

  def operation_checkpoint_covered_head_sequence(attrs) do
    dual_key_get(attrs, :operation_checkpoint_covered_head_sequence)
  end

  def operation_checkpoint_covered_head_hash(attrs) do
    case dual_key_get(attrs, :operation_checkpoint_covered_head_hash) do
      value when is_binary(value) -> Encoding.encode_base64url(value)
      _ -> nil
    end
  end

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  def delete(workspace_id, user_id, device_id, key_version) do
    from(k in WorkspaceEncryptedKey,
      where:
        k.workspace_id == ^workspace_id and
          k.user_id == ^user_id and
          k.device_id == ^device_id and
          k.key_version == ^key_version
    )
    |> Repo.delete_all()
  end

  def list_for_device(workspace_id, user_id, device_id) do
    from(k in WorkspaceEncryptedKey,
      where:
        k.workspace_id == ^workspace_id and
          k.user_id == ^user_id and
          k.device_id == ^device_id,
      order_by: [asc: k.key_version]
    )
    |> Repo.all()
  end

  def user_has_active_kek?(workspace_id, user_id) do
    from(k in WorkspaceEncryptedKey,
      where:
        k.workspace_id == ^workspace_id and
          k.user_id == ^user_id and
          k.is_active == true,
      select: count()
    )
    |> Repo.one()
    |> Kernel.>(0)
  end

  def max_active_kek_version(workspace_id) do
    from(k in WorkspaceEncryptedKey,
      where: k.workspace_id == ^workspace_id and k.is_active == true,
      select: max(k.key_version)
    )
    |> Repo.one()
  end

  defp active_device?(device_id) do
    from(d in RefMD.Devices.Device,
      where:
        d.id == ^device_id and is_nil(d.revoked_at) and
          is_nil(d.identity_wipe_required_at)
    )
    |> Repo.exists?()
  end

  defp active_device_record!(device_id) do
    case Devices.get_device(device_id) do
      %{revoked_at: nil, identity_wipe_required_at: nil} = device -> device
      _ -> raise ArgumentError, "device_inactive"
    end
  end

  defp fetch_attr!(attrs, key) do
    Map.fetch!(attrs, key)
  rescue
    KeyError -> Map.fetch!(attrs, Atom.to_string(key))
  end

  defp verify_device_key_wrap_signature(attrs, sender_device) do
    case SignedPQ.verify_signature(attrs, sender_device.hybrid_signing_public_key_material) do
      :ok -> :ok
      {:error, _reason} -> {:error, :invalid_workspace_device_kek_wrap}
    end
  end

  defp encode_signing_key_id(value) when is_binary(value),
    do: Base.url_encode64(value, padding: false)

  defp encode_wrap_binary(value) when is_binary(value),
    do: Base.url_encode64(value, padding: false)

  defp serialize_key_directory_checkpoint(checkpoint),
    do: %{payload: checkpoint.payload, signatures: checkpoint.signatures}

  defp serialize_key_directory_event(event),
    do: %{payload: event.payload, signatures: event.signatures}
end
