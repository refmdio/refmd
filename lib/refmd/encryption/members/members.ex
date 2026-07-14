defmodule RefMD.Encryption.Members do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Encoding, Hash, JCS}
  alias RefMD.Devices

  alias RefMD.Encryption.{
    Users,
    WorkspaceEncryptedKey,
    WorkspaceMemberEnvelope
  }

  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.Workspaces, as: WorkspaceEncryption
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo
  alias RefMD.Workspaces, as: WorkspaceContext

  def save_with_key_directory(workspace_id, envelopes, workspace_events, workspace_checkpoint)
      when is_list(envelopes) and is_list(workspace_events) and is_map(workspace_checkpoint) do
    Repo.transaction(fn ->
      validate_member_envelope_wraps_for_write!(
        workspace_id,
        envelopes,
        workspace_events,
        workspace_checkpoint
      )

      KeyDirectory.append_signed_scope!(
        "workspace",
        workspace_id,
        workspace_events,
        workspace_checkpoint,
        checkpoint_signer_kind: "device"
      )

      Enum.each(envelopes, fn envelope ->
        WorkspaceEncryption.assert_operation_checkpoint_matches_current_pin!(
          "workspace",
          workspace_id,
          envelope
        )
      end)

      case save(workspace_id, envelopes) do
        {:ok, result} -> result
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def save_with_key_directory(_, _, _, _), do: {:error, :missing_key_directory}

  def prepare_client_envelope(
        container,
        metadata,
        validation_context,
        event,
        workspace_checkpoint
      )
      when is_map(container) and is_map(metadata) and is_map(validation_context) do
    attrs = build_member_envelope_attrs!(container, metadata)

    case validate_member_envelope_wrap(
           attrs,
           Map.put(validation_context, :workspace_checkpoint, workspace_checkpoint),
           Map.fetch!(validation_context, :target_identity),
           Map.fetch!(validation_context, :sender_device),
           [event]
         ) do
      :ok -> {:ok, attrs}
      {:error, :invalid_workspace_member_kek_wrap} -> {:error, :invalid_workspace_member_kek_wrap}
    end
  rescue
    _ -> {:error, :invalid_workspace_member_kek_wrap}
  end

  def validate_invitation_member_envelope(member_envelope, context)
      when is_map(member_envelope) and is_map(context) do
    attrs = SignedPQ.attrs_from_container_params!(member_envelope)
    target_user_id = Map.fetch!(context, :target_user_id)
    {sender_user_id, sender_device_id} = invitation_member_sender(context, target_user_id)
    identity = identity_public_key!(target_user_id)
    sender_device = active_device_record!(sender_device_id)
    key_directory = Map.fetch!(context, :key_directory)

    member_envelope_hash = member_envelope_binding_hash!(attrs)

    unless valid_invitation_member_sender?(identity, sender_device, sender_user_id) do
      throw(:invalid_invitation_member_envelope)
    end

    expected_resource = %{
      "workspace_id" => Map.fetch!(context, :workspace_id),
      "target_user_id" => target_user_id,
      "kek_version" => Map.fetch!(context, :kek_version)
    }

    unless valid_invitation_member_envelope_attrs?(
             context,
             member_envelope,
             attrs,
             expected_resource,
             sender_user_id,
             sender_device_id,
             sender_device.signing_key_id,
             identity.encryption_key_id
           ) do
      throw(:invalid_invitation_member_envelope)
    end

    :ok = validate_invitation_signed_context!(context, attrs, key_directory)

    validate_invitation_member_envelope_admission!(
      context,
      attrs,
      member_envelope_hash,
      key_directory
    )

    case SignedPQ.verify_signature(attrs, sender_device.hybrid_signing_public_key_material) do
      :ok -> {:ok, %{member_envelope_hash: member_envelope_hash}}
      {:error, _reason} -> throw(:invalid_invitation_member_envelope)
    end
  rescue
    _ -> {:error, :invalid_member_envelope}
  catch
    :invalid_invitation_member_envelope -> {:error, :invalid_member_envelope}
  end

  defp validate_member_envelope_wraps_for_write!(
         workspace_id,
         envelopes,
         workspace_events,
         workspace_checkpoint
       ) do
    if length(envelopes) != length(workspace_events) do
      Repo.rollback(:invalid_workspace_member_kek_wrap)
    end

    envelopes
    |> Enum.zip(workspace_events)
    |> Enum.each(fn {attrs, event} ->
      sender_device = active_device_record!(fetch_attr!(attrs, :sender_device_id))
      target_identity = identity_public_key_for_wrap!(attrs)

      :ok =
        validate_member_envelope_wrap(
          attrs,
          %{
            workspace_id: workspace_id,
            sender_user_id: sender_device.user_id,
            workspace_checkpoint: workspace_checkpoint
          },
          target_identity,
          sender_device,
          [event]
        )
    end)
  rescue
    _ -> Repo.rollback(:invalid_workspace_member_kek_wrap)
  end

  def build_member_envelope_attrs!(container, metadata) do
    container
    |> SignedPQ.attrs_from_container_params!()
    |> Map.merge(metadata)
  end

  def validate_member_envelope_wrap(
        attrs,
        context,
        target_identity,
        sender_device,
        key_directory_events
      ) do
    key_checkpoint = key_checkpoint_context!(attrs, context)

    case SignedPQ.validate_workspace_member_kek(attrs, %{
           workspace_id: Map.fetch!(context, :workspace_id),
           sender_user_id: Map.fetch!(context, :sender_user_id),
           target_user_id: target_identity.user_id,
           sender_device_id: sender_device.id,
           key_version: attrs.key_version,
           operation_checkpoint_sequence: attrs.operation_checkpoint_sequence,
           operation_checkpoint_hash: Encoding.encode_base64url(attrs.operation_checkpoint_hash),
           key_checkpoint_sequence: key_checkpoint.sequence,
           key_checkpoint_hash: key_checkpoint.hash,
           key_directory_events: key_directory_events
         }) do
      :ok ->
        cond do
          encode_wrap_binary(attrs.sender_signing_key_id) != sender_device.signing_key_id ->
            {:error, :invalid_workspace_member_kek_wrap}

          encode_wrap_binary(attrs.recipient_key_id) != target_identity.encryption_key_id ->
            {:error, :invalid_workspace_member_kek_wrap}

          true ->
            verify_member_envelope_signature(attrs, sender_device)
        end

      {:error, _reason} ->
        {:error, :invalid_workspace_member_kek_wrap}
    end
  rescue
    _ -> {:error, :invalid_workspace_member_kek_wrap}
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

  defp member_envelope_binding_hash!(attrs) do
    attrs
    |> Map.fetch!(:wrap_event_body_hash)
    |> Encoding.encode_base64url()
  end

  defp valid_invitation_member_sender?(identity, sender_device, sender_user_id) do
    is_map(identity.hybrid_encryption_public_key_material) and
      sender_device.user_id == sender_user_id
  end

  defp invitation_member_sender(
         %{recipient_delivery_attempt: nil, requester_device_id: device_id},
         target_user_id
       ),
       do: {target_user_id, device_id}

  defp invitation_member_sender(%{recipient_delivery_attempt: attempt}, _target_user_id) do
    freshness = attempt.approved_artifacts["redeem_freshness_proof"]

    {
      get_in(freshness, ["authoritative_device", "user_id"]),
      get_in(freshness, ["authoritative_device", "device_id"])
    }
  end

  defp valid_invitation_member_envelope_attrs?(
         context,
         member_envelope,
         attrs,
         expected_resource,
         expected_sender_user_id,
         expected_sender_device_id,
         expected_sender_signing_key_id,
         expected_recipient_key_id
       ) do
    target_user_id = Map.fetch!(context, :target_user_id)
    kek_version = Map.fetch!(context, :kek_version)
    workspace_id = Map.fetch!(context, :workspace_id)
    expected_event_scope = %{"scope_kind" => "workspace", "scope_id" => workspace_id}

    envelope_values_match?(
      target_user_id,
      expected_sender_device_id,
      kek_version,
      member_envelope,
      attrs,
      expected_resource,
      expected_event_scope
    ) and
      envelope_sender_matches?(
        attrs,
        expected_sender_user_id,
        expected_sender_device_id,
        expected_sender_signing_key_id
      ) and
      envelope_recipient_matches?(attrs, target_user_id, expected_recipient_key_id)
  end

  defp envelope_values_match?(
         target_user_id,
         requester_device_id,
         kek_version,
         member_envelope,
         attrs,
         expected_resource,
         expected_event_scope
       ) do
    [
      {member_envelope["target_user_id"], target_user_id},
      {member_envelope["sender_device_id"], requester_device_id},
      {member_envelope["key_version"], kek_version},
      {attrs.purpose, "workspace_member_kek_wrap"},
      {attrs.resource, expected_resource},
      {attrs.event_scope, expected_event_scope}
    ]
    |> Enum.all?(fn {actual, expected} -> actual == expected end)
  end

  defp envelope_sender_matches?(
         attrs,
         sender_user_id,
         sender_device_id,
         expected_signing_key_id
       ) do
    [
      {attrs.sender["user_id"], sender_user_id},
      {attrs.sender["device_id"], sender_device_id},
      {attrs.sender["signing_key_id"], expected_signing_key_id}
    ]
    |> Enum.all?(fn {actual, expected} -> actual == expected end)
  end

  defp envelope_recipient_matches?(attrs, target_user_id, expected_recipient_key_id) do
    [
      {attrs.recipient["recipient_kind"], "user_identity"},
      {attrs.recipient["user_id"], target_user_id},
      {attrs.recipient["encryption_key_id"], expected_recipient_key_id},
      {Encoding.encode_base64url(attrs.recipient_key_id), expected_recipient_key_id}
    ]
    |> Enum.all?(fn {actual, expected} -> actual == expected end)
  end

  defp validate_invitation_signed_context!(context, attrs, key_directory) do
    {sender_user_id, sender_device_id} =
      invitation_member_sender(context, Map.fetch!(context, :target_user_id))

    recipient_checkpoint = invitation_recipient_checkpoint(context, attrs)

    case SignedPQ.validate_invitation_workspace_member_kek(attrs, %{
           workspace_id: Map.fetch!(context, :workspace_id),
           target_user_id: Map.fetch!(context, :target_user_id),
           sender_user_id: sender_user_id,
           sender_device_id: sender_device_id,
           key_version: Map.fetch!(context, :kek_version),
           key_checkpoint_sequence: attrs.sender["key_checkpoint_sequence"],
           key_checkpoint_hash: attrs.sender["key_checkpoint_hash"],
           recipient_key_scope_kind: recipient_checkpoint.scope_kind,
           recipient_key_checkpoint_sequence: recipient_checkpoint.sequence,
           recipient_key_checkpoint_hash: recipient_checkpoint.hash,
           operation_checkpoint_sequence: attrs.operation_checkpoint_sequence,
           operation_checkpoint_hash: Encoding.encode_base64url(attrs.operation_checkpoint_hash),
           key_directory_events: Map.fetch!(key_directory, :events)
         }) do
      :ok -> :ok
      {:error, _reason} -> throw(:invalid_invitation_member_envelope)
    end
  end

  defp invitation_recipient_checkpoint(%{recipient_delivery_attempt: attempt}, _attrs)
       when not is_nil(attempt) do
    %{
      scope_kind: "user",
      sequence: attempt.target_key_checkpoint_sequence,
      hash: attempt.target_key_checkpoint_hash
    }
  end

  defp invitation_recipient_checkpoint(_context, attrs) do
    %{
      scope_kind: "workspace",
      sequence: attrs.sender["key_checkpoint_sequence"],
      hash: attrs.sender["key_checkpoint_hash"]
    }
  end

  defp validate_invitation_member_envelope_admission!(
         context,
         attrs,
         member_envelope_hash,
         %{events: events, checkpoint: checkpoint}
       )
       when is_list(events) and is_map(checkpoint) do
    workspace_id = Map.fetch!(context, :workspace_id)
    invitation_id = Map.fetch!(context, :invitation_id)
    target_user_id = Map.fetch!(context, :target_user_id)
    requester_device_id = Map.fetch!(context, :requester_device_id)
    kek_version = Map.fetch!(context, :kek_version)
    wrap_event = wrap_issued_event!(events, attrs)
    wrap_payload = event_payload!(wrap_event)
    event = redeemed_event!(events)
    event_payload = event_payload!(event)
    body = event_payload["body"]
    checkpoint_payload = envelope_payload!(checkpoint)
    covered_head = checkpoint_payload["covered_event_head"]
    checkpoint_hash = Hash.blake3_base64url(JCS.canonical_bytes!(checkpoint_payload))

    true = wrap_payload["event_type"] == "wrap_issued"
    true = wrap_payload["scope_kind"] == "workspace"
    true = wrap_payload["scope_id"] == workspace_id
    true = wrap_payload["sequence"] == attrs.wrap_event_sequence

    true =
      Hash.blake3_base64url(JCS.canonical_bytes!(wrap_payload)) ==
        Encoding.encode_base64url(attrs.wrap_event_hash)

    true = event_payload["event_type"] == "workspace_invitation_redeemed"
    true = event_payload["scope_kind"] == "workspace"
    true = event_payload["scope_id"] == workspace_id
    true = event_payload["sequence"] == attrs.wrap_event_sequence + 1

    true =
      event_payload["previous_event_hash"] == Encoding.encode_base64url(attrs.wrap_event_hash)

    true = body["workspace_id"] == workspace_id
    true = body["invitation_id"] == invitation_id
    true = body["redeemed_user_id"] == target_user_id
    true = body["redeemed_device_id"] == requester_device_id
    true = body["member_envelope_key_version"] == kek_version
    true = body["member_envelope_hash"] == member_envelope_hash

    true = checkpoint_payload["scope_kind"] == "workspace"
    true = checkpoint_payload["scope_id"] == workspace_id
    true = checkpoint_payload["sequence"] == attrs.operation_checkpoint_sequence
    true = checkpoint_hash == Encoding.encode_base64url(attrs.operation_checkpoint_hash)

    true = is_map(covered_head)
    true = covered_head["head_sequence"] >= event_payload["sequence"]
    true = attrs.operation_checkpoint_covered_head_sequence == covered_head["head_sequence"]

    true =
      Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash) ==
        covered_head["head_hash"]
  end

  defp validate_invitation_member_envelope_admission!(_, _, _, _),
    do: throw(:invalid_invitation_member_envelope)

  defp redeemed_event!(events) do
    case Enum.filter(events, fn event ->
           event_payload!(event)["event_type"] == "workspace_invitation_redeemed"
         end) do
      [event] -> event
      _ -> throw(:invalid_invitation_member_envelope)
    end
  end

  defp wrap_issued_event!(events, attrs) do
    expected_hash = Encoding.encode_base64url(attrs.wrap_event_hash)

    case Enum.filter(events, fn event ->
           payload = event_payload!(event)

           payload["event_type"] == "wrap_issued" and
             Hash.blake3_base64url(JCS.canonical_bytes!(payload)) == expected_hash
         end) do
      [event] -> event
      _ -> throw(:invalid_invitation_member_envelope)
    end
  end

  defp event_payload!(%{"payload" => payload}) when is_map(payload), do: payload
  defp event_payload!(%{payload: payload}) when is_map(payload), do: payload
  defp event_payload!(_), do: throw(:invalid_invitation_member_envelope)

  defp envelope_payload!(%{"payload" => payload}) when is_map(payload), do: payload
  defp envelope_payload!(%{payload: payload}) when is_map(payload), do: payload
  defp envelope_payload!(_), do: throw(:invalid_invitation_member_envelope)

  def operation_checkpoint_envelope(%{operation_checkpoint_sequence: sequence} = envelope)
      when is_integer(sequence) do
    expected_hash = Base.url_encode64(envelope.operation_checkpoint_hash, padding: false)

    case KeyDirectory.checkpoints_between(
           "workspace",
           envelope.workspace_id,
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

  def save(workspace_id, envelopes) do
    now = DateTime.utc_now()

    parsed =
      Enum.reduce_while(envelopes, {:ok, []}, fn env, {:ok, acc} ->
        try do
          attrs = workspace_member_envelope_attrs!(workspace_id, env)

          changeset =
            %WorkspaceMemberEnvelope{created_at: now}
            |> WorkspaceMemberEnvelope.changeset(attrs)

          {:cont, {:ok, [changeset | acc]}}
        rescue
          KeyError -> {:halt, {:error, :invalid_signed_wrap}}
          ArgumentError -> {:halt, {:error, :invalid_signed_wrap}}
        end
      end)

    case parsed do
      {:error, reason} ->
        {:error, reason}

      {:ok, changesets} ->
        Repo.transaction(fn ->
          Enum.each(changesets, &insert_envelope_or_rollback/1)
        end)
    end
  end

  def get(workspace_id, user_id) do
    from(e in WorkspaceMemberEnvelope,
      where: e.workspace_id == ^workspace_id and e.target_user_id == ^user_id,
      order_by: [desc: :key_version],
      limit: 1
    )
    |> Repo.one()
  end

  def member_has_envelope?(workspace_id, user_id, key_version) do
    from(e in WorkspaceMemberEnvelope,
      where:
        e.workspace_id == ^workspace_id and e.target_user_id == ^user_id and
          e.key_version == ^key_version,
      select: true,
      limit: 1
    )
    |> Repo.exists?()
  end

  def all_user_devices_have_key?(workspace_id, user_id, key_version) do
    active_device_ids =
      from(d in RefMD.Devices.Device,
        where:
          d.user_id == ^user_id and is_nil(d.revoked_at) and
            is_nil(d.identity_wipe_required_at),
        select: d.id
      )
      |> Repo.all()
      |> MapSet.new()

    covered_device_ids =
      from(k in WorkspaceEncryptedKey,
        where:
          k.workspace_id == ^workspace_id and
            k.user_id == ^user_id and
            k.key_version == ^key_version and
            k.is_active == true,
        select: k.device_id
      )
      |> Repo.all()
      |> MapSet.new()

    MapSet.subset?(active_device_ids, covered_device_ids)
  end

  def all_workspace_member_devices_have_key?(workspace_id, key_version) do
    active_devices =
      active_workspace_kek_recipient_devices(workspace_id)
      |> MapSet.new()

    covered_devices =
      from(k in WorkspaceEncryptedKey,
        join: d in RefMD.Devices.Device,
        on: d.id == k.device_id and d.user_id == k.user_id,
        where:
          k.workspace_id == ^workspace_id and
            k.key_version == ^key_version and
            k.is_active == true and
            is_nil(d.revoked_at) and
            is_nil(d.identity_wipe_required_at),
        select: {k.user_id, k.device_id, d.encryption_key_id, k.recipient_key_id}
      )
      |> Repo.all()
      |> Enum.filter(fn {_user_id, _device_id, encryption_key_id, recipient_key_id} ->
        Encoding.encode_base64url(recipient_key_id) == encryption_key_id
      end)
      |> Enum.map(fn {user_id, device_id, encryption_key_id, _recipient_key_id} ->
        {user_id, device_id, encryption_key_id}
      end)
      |> MapSet.new()

    MapSet.subset?(active_devices, covered_devices)
  end

  def all_members_have_envelope?(workspace_id, key_version) do
    registered_member_ids =
      from(wm in RefMD.Workspaces.WorkspaceMember,
        join: r in RefMD.Workspaces.WorkspaceRole,
        on: r.id == wm.role_id,
        join: u in RefMD.Users.User,
        on: u.id == wm.user_id,
        where:
          wm.workspace_id == ^workspace_id and u.account_type != "guest" and
            r.base_role != "guest",
        select: wm.user_id
      )
      |> Repo.all()
      |> MapSet.new()

    admitted_guest_ids =
      workspace_id
      |> active_workspace_kek_recipient_devices()
      |> Enum.map(&elem(&1, 0))
      |> Enum.filter(&WorkspaceContext.guest_user?/1)
      |> MapSet.new()

    member_ids = MapSet.union(registered_member_ids, admitted_guest_ids)

    covered_member_ids =
      from(e in WorkspaceMemberEnvelope,
        where: e.workspace_id == ^workspace_id and e.key_version == ^key_version,
        select: e.target_user_id
      )
      |> Repo.all()
      |> MapSet.new()

    MapSet.subset?(member_ids, covered_member_ids)
  end

  defp workspace_member_envelope_attrs!(workspace_id, %{wrap_protocol: _} = attrs) do
    attrs = Map.merge(attrs, %{workspace_id: workspace_id})
    validate_member_envelope_attrs!(attrs)
    attrs
  end

  defp workspace_member_envelope_attrs!(workspace_id, env) do
    attrs =
      Map.merge(SignedPQ.attrs_from_container_params!(env), %{
        workspace_id: workspace_id,
        target_user_id: env["target_user_id"],
        key_version: env["key_version"],
        sender_device_id: env["sender_device_id"]
      })

    validate_member_envelope_attrs!(attrs)
    attrs
  end

  defp validate_member_envelope_attrs!(attrs) do
    if WorkspaceContext.guest_user?(attrs.target_user_id) do
      validate_workspace_guest_successor_envelope!(attrs)
    else
      case WorkspaceContext.get_member_role(attrs.workspace_id, attrs.target_user_id) do
        role when is_binary(role) and role != "guest" -> :ok
        _ -> raise ArgumentError, "target_member_invalid"
      end
    end

    unless member_envelope_checkpoint_current?(attrs) do
      raise ArgumentError, "operation_checkpoint_mismatch"
    end

    :ok
  end

  defp validate_workspace_guest_successor_envelope!(attrs) do
    sender_device = active_device_record!(attrs.sender_device_id)
    pending = Users.get_pending_identity_public_key(attrs.target_user_id, lock: "FOR SHARE")
    recipient_key_id = attrs.recipient_key_id |> encode_wrap_binary()

    unless sender_device.user_id == attrs.target_user_id and
             WorkspaceContext.authorize_workspace_guest_access(
               attrs.workspace_id,
               attrs.target_user_id
             ) == :ok and
             KeyDirectory.active_workspace_scope_guest_device_admitted?(
               attrs.workspace_id,
               attrs.target_user_id,
               attrs.sender_device_id
             ) and
             pending != nil and pending.encryption_key_id == recipient_key_id do
      raise ArgumentError, "target_member_invalid"
    end
  end

  defp member_envelope_checkpoint_current?(attrs) do
    pin = KeyDirectory.current_pin("workspace", attrs.workspace_id)

    pin != nil and
      WorkspaceEncryption.operation_checkpoint_sequence(attrs) == pin.checkpoint_sequence and
      WorkspaceEncryption.operation_checkpoint_hash(attrs) == pin.checkpoint_hash and
      WorkspaceEncryption.operation_checkpoint_covered_head_sequence(attrs) ==
        pin.event_head_sequence and
      WorkspaceEncryption.operation_checkpoint_covered_head_hash(attrs) == pin.event_head_hash
  end

  defp insert_envelope_or_rollback(changeset) do
    case Repo.insert(changeset,
           on_conflict:
             {:replace,
              [
                :sender_device_id,
                :created_at,
                :wrap_protocol,
                :wrap_version,
                :suite_id,
                :suite_rank,
                :purpose,
                :resource,
                :sender,
                :recipient,
                :event_scope,
                :wrap_event_sequence,
                :wrap_event_hash,
                :wrap_event_body_hash,
                :operation_checkpoint_sequence,
                :operation_checkpoint_hash,
                :operation_checkpoint_covered_head_sequence,
                :operation_checkpoint_covered_head_hash,
                :wrap_body_hash,
                :recipient_key_id,
                :sender_signing_key_id,
                :hpke_enc,
                :hpke_ciphertext,
                :signature_protocol,
                :signature_version,
                :signature_suite_id,
                :signature_suite_rank,
                :transcript_hash,
                :ed25519_signature,
                :mldsa65_signature
              ]},
           conflict_target: [:workspace_id, :target_user_id, :key_version]
         ) do
      {:ok, _} ->
        :ok

      {:error, %Ecto.Changeset{errors: errors} = cs} ->
        if member_removed_during_rotation?(errors) do
          :ok
        else
          Repo.rollback({:invalid_envelope, cs})
        end
    end
  end

  defp member_removed_during_rotation?(errors) do
    case Keyword.get(errors, :target_user_id) do
      {_msg, opts} -> opts[:constraint] == :foreign
      _ -> false
    end
  end

  defp verify_member_envelope_signature(attrs, sender_device) do
    case SignedPQ.verify_signature(attrs, sender_device.hybrid_signing_public_key_material) do
      :ok -> :ok
      {:error, _reason} -> {:error, :invalid_workspace_member_kek_wrap}
    end
  end

  defp encode_wrap_binary(value) when is_binary(value),
    do: Base.url_encode64(value, padding: false)

  defp active_device_record!(device_id) do
    case Devices.get_device(device_id) do
      %{revoked_at: nil} = device -> device
      _ -> raise ArgumentError, "device_inactive"
    end
  end

  defp identity_public_key!(user_id) do
    case Users.identity_key_for_new_encryption(user_id, lock: "FOR SHARE") do
      {:ok, identity} -> identity
      {:error, reason} -> raise ArgumentError, Atom.to_string(reason)
    end
  end

  defp identity_public_key_for_wrap!(attrs) do
    user_id = fetch_attr!(attrs, :target_user_id)
    recipient_key_id = attrs |> fetch_attr!(:recipient_key_id) |> encode_wrap_binary()
    current = Users.get_identity_public_key(user_id, lock: "FOR SHARE")
    pending = Users.get_pending_identity_public_key(user_id, lock: "FOR SHARE")

    cond do
      pending && pending.encryption_key_id == recipient_key_id ->
        pending

      current && current.encryption_key_id == recipient_key_id ->
        identity_public_key!(user_id)

      true ->
        raise ArgumentError, "identity_key_missing"
    end
  end

  defp fetch_attr!(attrs, key) do
    Map.fetch!(attrs, key)
  rescue
    KeyError -> Map.fetch!(attrs, Atom.to_string(key))
  end

  defp active_workspace_kek_recipient_devices(workspace_id) do
    Enum.uniq(
      active_workspace_member_kek_recipient_devices(workspace_id) ++
        active_workspace_guest_kek_recipient_devices(workspace_id)
    )
  end

  defp active_workspace_member_kek_recipient_devices(workspace_id) do
    from(d in RefMD.Devices.Device,
      join: u in RefMD.Users.User,
      on: u.id == d.user_id,
      join: wm in RefMD.Workspaces.WorkspaceMember,
      on: wm.user_id == d.user_id and wm.workspace_id == ^workspace_id,
      join: r in RefMD.Workspaces.WorkspaceRole,
      on: r.id == wm.role_id,
      where:
        u.account_type != "guest" and r.base_role != "guest" and is_nil(d.revoked_at) and
          is_nil(d.identity_wipe_required_at),
      select: {d.user_id, d.id, d.encryption_key_id}
    )
    |> Repo.all()
  end

  defp active_workspace_guest_kek_recipient_devices(workspace_id) do
    from(d in RefMD.Devices.Device,
      join: u in RefMD.Users.User,
      on: u.id == d.user_id,
      join: g in RefMD.Workspaces.WorkspaceGuestGrant,
      on: g.user_id == d.user_id and g.workspace_id == ^workspace_id,
      where:
        u.account_type == "guest" and g.scope_kind == "workspace" and
          is_nil(g.revoked_at) and is_nil(d.revoked_at) and
          is_nil(d.identity_wipe_required_at),
      select: {d.user_id, d.id, d.encryption_key_id}
    )
    |> Repo.all()
    |> Enum.filter(fn {user_id, device_id, _encryption_key_id} ->
      KeyDirectory.active_workspace_scope_guest_device_admitted?(
        workspace_id,
        user_id,
        device_id
      )
    end)
  end
end
