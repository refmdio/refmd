defmodule RefMD.Encryption.KeyDirectory.Store do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Suite
  alias RefMD.Encryption.KeyDirectory.{Checkpoint, Event, Payload, Pin, Protocol}
  alias RefMD.Repo

  @valid_scope_kinds ["user", "workspace"]

  @spec insert_event!(map(), [map()]) :: Event.t()
  def insert_event!(payload, signatures) when is_list(signatures) and signatures != [] do
    Payload.assert_event_payload!(payload)

    %Event{}
    |> Event.changeset(%{
      scope_kind: payload["scope_kind"],
      scope_id: payload["scope_id"],
      sequence: payload["sequence"],
      event_type: payload["event_type"],
      event_hash: Protocol.event_hash(payload),
      event_body_hash: Protocol.event_body_hash(payload["body"]),
      previous_event_hash: Map.get(payload, "previous_event_hash"),
      payload: payload,
      signatures: signatures
    })
    |> Repo.insert!()
  end

  def insert_event!(_, _), do: raise(ArgumentError, "key_directory_event_signatures_required")

  @spec insert_checkpoint!(map(), [map()]) :: Checkpoint.t()
  def insert_checkpoint!(payload, signatures) when is_list(signatures) and signatures != [] do
    Payload.assert_checkpoint_payload!(payload)
    allowed_suite_ids_hash = Suite.canonical_allowed_suite_ids_hash(payload)

    %Checkpoint{}
    |> Checkpoint.changeset(%{
      scope_kind: payload["scope_kind"],
      scope_id: payload["scope_id"],
      sequence: payload["sequence"],
      checkpoint_hash: Protocol.checkpoint_hash(payload),
      previous_checkpoint_hash: Map.get(payload, "previous_checkpoint_hash"),
      covered_event_head_sequence: payload["covered_event_head"]["head_sequence"],
      covered_event_head_hash: payload["covered_event_head"]["head_hash"],
      suite_policy_version: payload["suite_policy_version"],
      min_suite_rank: payload["min_suite_rank"],
      allowed_suite_ids_hash: allowed_suite_ids_hash,
      payload: payload,
      signatures: signatures
    })
    |> Repo.insert!()
  end

  def insert_checkpoint!(_, _),
    do: raise(ArgumentError, "key_directory_checkpoint_signatures_required")

  @spec current_checkpoint(binary(), Ecto.UUID.t()) :: Checkpoint.t() | nil
  def current_checkpoint(scope_kind, scope_id)
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) do
    Checkpoint
    |> where([c], c.scope_kind == ^scope_kind and c.scope_id == ^scope_id)
    |> order_by([c], desc: c.sequence)
    |> limit(1)
    |> Repo.one()
    |> case do
      %Checkpoint{} = checkpoint ->
        if stored_checkpoint_integrity?(checkpoint),
          do: checkpoint,
          else: raise(ArgumentError, "key_directory_checkpoint_storage_mismatch")

      nil ->
        nil
    end
  end

  def current_checkpoint(_, _), do: nil

  @spec current_pin(binary(), Ecto.UUID.t()) :: Pin.t() | nil
  def current_pin(scope_kind, scope_id)
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) do
    with %Checkpoint{} = checkpoint <- current_checkpoint(scope_kind, scope_id) do
      checkpoint_pin(checkpoint)
    end
  end

  def current_pin(_, _), do: nil

  @spec assert_stored_checkpoint!(Checkpoint.t()) :: :ok
  def assert_stored_checkpoint!(%Checkpoint{} = checkpoint) do
    if stored_checkpoint_integrity?(checkpoint),
      do: :ok,
      else: raise(ArgumentError, "key_directory_checkpoint_storage_mismatch")
  end

  @spec assert_stored_event!(Event.t()) :: :ok
  def assert_stored_event!(%Event{} = event) do
    if stored_event_integrity?(event),
      do: :ok,
      else: raise(ArgumentError, "key_directory_event_storage_mismatch")
  end

  @spec active_key_material_in_current_checkpoint(binary(), Ecto.UUID.t(), binary()) ::
          {:ok, map()} | {:error, :not_found}
  def active_key_material_in_current_checkpoint(scope_kind, scope_id, key_id)
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_binary(key_id) do
    with %Checkpoint{} = checkpoint <- current_checkpoint(scope_kind, scope_id),
         %{} = entry <- find_active_key_entry(checkpoint.payload, key_id) do
      {:ok, entry["key_material"]}
    else
      _ -> {:error, :not_found}
    end
  end

  def active_key_material_in_current_checkpoint(_, _, _), do: {:error, :not_found}

  @spec active_owner_signing_material_in_current_checkpoint(
          binary(),
          Ecto.UUID.t(),
          binary(),
          Ecto.UUID.t()
        ) :: {:ok, map()} | {:error, :not_found}
  def active_owner_signing_material_in_current_checkpoint(
        scope_kind,
        scope_id,
        owner_kind,
        owner_id
      )
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_binary(owner_kind) and
             is_binary(owner_id) do
    with %Checkpoint{} = checkpoint <- current_checkpoint(scope_kind, scope_id),
         %{} = entry <-
           find_active_owner_signing_key_entry(checkpoint.payload, owner_kind, owner_id) do
      {:ok, entry["key_material"]}
    else
      _ -> {:error, :not_found}
    end
  end

  def active_owner_signing_material_in_current_checkpoint(_, _, _, _),
    do: {:error, :not_found}

  @spec active_owner_encryption_material_in_current_checkpoint(
          binary(),
          Ecto.UUID.t(),
          binary(),
          Ecto.UUID.t()
        ) :: {:ok, map()} | {:error, :not_found}
  def active_owner_encryption_material_in_current_checkpoint(
        scope_kind,
        scope_id,
        owner_kind,
        owner_id
      )
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_binary(owner_kind) and
             is_binary(owner_id) do
    with %Checkpoint{} = checkpoint <- current_checkpoint(scope_kind, scope_id),
         %{} = entry <-
           find_active_owner_encryption_key_entry(checkpoint.payload, owner_kind, owner_id) do
      {:ok, entry["key_material"]}
    else
      _ -> {:error, :not_found}
    end
  end

  def active_owner_encryption_material_in_current_checkpoint(_, _, _, _),
    do: {:error, :not_found}

  @spec active_key_material_at_checkpoint(
          binary(),
          Ecto.UUID.t(),
          binary(),
          pos_integer(),
          binary()
        ) :: {:ok, map()} | {:error, :not_found}
  def active_key_material_at_checkpoint(
        scope_kind,
        scope_id,
        key_id,
        checkpoint_sequence,
        checkpoint_hash
      )
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_binary(key_id) and
             is_integer(checkpoint_sequence) and checkpoint_sequence > 0 and
             is_binary(checkpoint_hash) do
    with %Checkpoint{} = checkpoint <-
           Repo.get_by(Checkpoint,
             scope_kind: scope_kind,
             scope_id: scope_id,
             sequence: checkpoint_sequence,
             checkpoint_hash: checkpoint_hash
           ),
         %{} = entry <- find_active_key_entry(checkpoint.payload, key_id) do
      {:ok, entry["key_material"]}
    else
      _ -> {:error, :not_found}
    end
  end

  def active_key_material_at_checkpoint(_, _, _, _, _), do: {:error, :not_found}

  @spec initial_checkpoint_pin!(Checkpoint.t()) :: map()
  def initial_checkpoint_pin!(%Checkpoint{sequence: 1} = checkpoint),
    do: checkpoint_pin(checkpoint)

  def initial_checkpoint_pin!(_), do: raise(ArgumentError, "initial_checkpoint_sequence_invalid")

  @spec advance_pin!(Pin.t(), Checkpoint.t()) :: Pin.t()
  def advance_pin!(%Pin{} = pin, %Checkpoint{} = checkpoint) do
    assert_literal!(
      checkpoint.previous_checkpoint_hash,
      pin.checkpoint_hash,
      "checkpoint_previous_hash_mismatch"
    )

    assert_literal!(
      checkpoint.sequence,
      pin.checkpoint_sequence + 1,
      "checkpoint_sequence_gap"
    )

    if checkpoint.covered_event_head_sequence <= pin.event_head_sequence,
      do: raise(ArgumentError, "event_head_not_advanced")

    checkpoint_pin(checkpoint)
  end

  @spec assert_pin_monotonic!(Pin.t(), map()) :: :ok
  def assert_pin_monotonic!(%Pin{} = pin, checkpoint_payload) do
    if checkpoint_payload["suite_policy_version"] < pin.suite_policy_version,
      do: raise(ArgumentError, "suite_policy_version_rollback")

    if checkpoint_payload["min_suite_rank"] < pin.min_suite_rank,
      do: raise(ArgumentError, "min_suite_rank_rollback")

    if checkpoint_payload["covered_event_head"]["head_sequence"] <= pin.event_head_sequence,
      do: raise(ArgumentError, "event_head_not_advanced")

    :ok
  end

  @spec events_up_to(binary(), Ecto.UUID.t(), pos_integer()) :: [Event.t()]
  def events_up_to(scope_kind, scope_id, head_sequence)
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_integer(head_sequence) and
             head_sequence > 0 do
    from(e in Event,
      where:
        e.scope_kind == ^scope_kind and e.scope_id == ^scope_id and
          e.sequence <= ^head_sequence,
      order_by: [asc: e.sequence]
    )
    |> Repo.all()
  end

  @spec events_after_until(binary(), Ecto.UUID.t(), non_neg_integer(), pos_integer()) :: [
          Event.t()
        ]
  def events_after_until(scope_kind, scope_id, after_sequence, head_sequence)
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_integer(after_sequence) and
             after_sequence >= 0 and is_integer(head_sequence) and head_sequence > after_sequence do
    from(e in Event,
      where:
        e.scope_kind == ^scope_kind and e.scope_id == ^scope_id and
          e.sequence > ^after_sequence and e.sequence <= ^head_sequence,
      order_by: [asc: e.sequence]
    )
    |> Repo.all()
  end

  def events_after_until(_, _, _, _), do: []

  @spec checkpoints_between(binary(), Ecto.UUID.t(), pos_integer(), pos_integer()) :: [
          Checkpoint.t()
        ]
  def checkpoints_between(scope_kind, scope_id, start_sequence, end_sequence)
      when scope_kind in @valid_scope_kinds and is_binary(scope_id) and is_integer(start_sequence) and
             start_sequence > 0 and is_integer(end_sequence) and end_sequence >= start_sequence do
    from(c in Checkpoint,
      where:
        c.scope_kind == ^scope_kind and c.scope_id == ^scope_id and
          c.sequence >= ^start_sequence and c.sequence <= ^end_sequence,
      order_by: [asc: c.sequence]
    )
    |> Repo.all()
  end

  def checkpoints_between(_, _, _, _), do: []

  defp find_active_key_entry(checkpoint_payload, key_id) do
    checkpoint_payload
    |> key_directory_authority_entries()
    |> Enum.find(fn
      %{"key_id" => ^key_id, "revoked_at" => _} -> false
      %{"key_id" => ^key_id} -> true
      _ -> false
    end)
  end

  defp find_active_owner_signing_key_entry(checkpoint_payload, owner_kind, owner_id) do
    checkpoint_payload
    |> key_directory_authority_entries()
    |> Enum.find(fn
      %{"revoked_at" => _} ->
        false

      %{"key_material" => %{"protocol" => "refmd.hybrid-signing-key-material"} = material} ->
        material["owner_kind"] == owner_kind and material["owner_id"] == owner_id

      _ ->
        false
    end)
  end

  defp find_active_owner_encryption_key_entry(checkpoint_payload, owner_kind, owner_id) do
    checkpoint_payload
    |> key_directory_authority_entries()
    |> Enum.find(fn
      %{"revoked_at" => _} ->
        false

      %{"key_material" => %{"protocol" => "refmd.hybrid-encryption-key-material"} = material} ->
        material["owner_kind"] == owner_kind and material["owner_id"] == owner_id

      _ ->
        false
    end)
  end

  defp key_directory_authority_entries(checkpoint_payload) do
    checkpoint_payload["identity_keys"] ++
      checkpoint_payload["device_keys"] ++
      Map.get(checkpoint_payload, "share_participant_keys", [])
  end

  defp checkpoint_pin(%Checkpoint{} = checkpoint) do
    %Pin{
      scope_kind: checkpoint.scope_kind,
      scope_id: checkpoint.scope_id,
      checkpoint_sequence: checkpoint.sequence,
      checkpoint_hash: checkpoint.checkpoint_hash,
      event_head_sequence: checkpoint.covered_event_head_sequence,
      event_head_hash: checkpoint.covered_event_head_hash,
      suite_policy_version: checkpoint.suite_policy_version,
      min_suite_rank: checkpoint.min_suite_rank,
      allowed_suite_ids_hash: checkpoint.allowed_suite_ids_hash
    }
  end

  defp stored_checkpoint_integrity?(%Checkpoint{} = checkpoint) do
    checkpoint.checkpoint_hash == Protocol.checkpoint_hash(checkpoint.payload) and
      checkpoint.previous_checkpoint_hash ==
        Map.get(checkpoint.payload, "previous_checkpoint_hash") and
      checkpoint.covered_event_head_sequence ==
        checkpoint.payload["covered_event_head"]["head_sequence"] and
      checkpoint.covered_event_head_hash == checkpoint.payload["covered_event_head"]["head_hash"] and
      checkpoint.suite_policy_version == checkpoint.payload["suite_policy_version"] and
      checkpoint.min_suite_rank == checkpoint.payload["min_suite_rank"] and
      checkpoint.allowed_suite_ids_hash ==
        Suite.canonical_allowed_suite_ids_hash(checkpoint.payload)
  rescue
    _ -> false
  end

  defp stored_event_integrity?(%Event{} = event) do
    event.scope_kind == event.payload["scope_kind"] and
      event.scope_id == event.payload["scope_id"] and
      event.sequence == event.payload["sequence"] and
      event.event_type == event.payload["event_type"] and
      event.event_hash == Protocol.event_hash(event.payload) and
      event.event_body_hash == Protocol.event_body_hash(event.payload["body"]) and
      event.previous_event_hash == Map.get(event.payload, "previous_event_hash")
  rescue
    _ -> false
  end

  defp assert_literal!(value, value, _error), do: :ok
  defp assert_literal!(_, _, error), do: raise(ArgumentError, error)
end
