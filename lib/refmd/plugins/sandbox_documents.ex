defmodule RefMD.Plugins.SandboxDocuments do
  @moduledoc false

  use GenServer

  @table __MODULE__
  @ttl_ms 60_000
  @served_frame_ttl_ms 60_000
  @active_frame_ttl_ms 12 * 60 * 60 * 1000
  @terminal_frame_ttl_ms 60_000
  @cleanup_interval_ms 30_000
  @frame_owner_key_fields [
    :workspace_id,
    :package_id,
    :application_id,
    :activation_id,
    :owner_scope_kind,
    :user_id,
    :device_id,
    :state_head_hash,
    :consent_head_hash,
    :consent_epoch,
    :capability_grant_id
  ]

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def create(attrs) do
    now = System.system_time(:millisecond)
    id = random_token(32)

    frame_generation = System.unique_integer([:positive, :monotonic])

    session =
      attrs
      |> Map.take([
        :workspace_id,
        :package_id,
        :application_id,
        :activation_id,
        :owner_scope_kind,
        :user_id,
        :device_id,
        :auth_session_id,
        :bundle_id,
        :bundle_hash,
        :manifest_hash,
        :resource_manifest_hash,
        :state_head_hash,
        :consent_head_hash,
        :consent_epoch,
        :capability_grant_id,
        :sandbox_document_frame_scope,
        :sandbox_document_variant,
        :wasm_browser_target
      ])
      |> Map.merge(%{
        id: id,
        expires_at_ms: now + @ttl_ms,
        boot_nonce: random_token(16),
        frame_generation: frame_generation,
        sandbox_document_frame_scope: frame_scope(attrs)
      })

    true = :ets.insert(@table, {id, session})

    insert_frame_marker(session, :pending, @ttl_ms, [], :replace_primary)

    session
  end

  def mark_served(session) when is_map(session) do
    insert_frame_marker(session, :served, @served_frame_ttl_ms)
    :ok
  end

  def activate_frame?(attrs) when is_map(attrs) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [{{:sandbox_frame, ^key}, %{frame_generation: ^frame_generation, state: state} = frame}] <-
           :ets.lookup(@table, {:sandbox_frame, key}),
         true <- frame_current?(attrs, frame),
         true <- state in [:served, :active] do
      insert_frame_marker(attrs, :active, @active_frame_ttl_ms)

      true
    else
      _ -> false
    end
  end

  def activate_frame?(_attrs), do: false

  def loadable_frame?(attrs) when is_map(attrs) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [{{:sandbox_frame, ^key}, %{frame_generation: ^frame_generation, state: state} = frame}] <-
           :ets.lookup(@table, {:sandbox_frame, key}),
         true <- frame_current?(attrs, frame) do
      state in [:served, :active]
    else
      _ -> false
    end
  end

  def loadable_frame?(_attrs), do: false

  def preload_frame?(attrs) when is_map(attrs) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [{{:sandbox_frame, ^key}, %{frame_generation: ^frame_generation, state: state} = frame}] <-
           :ets.lookup(@table, {:sandbox_frame, key}),
         true <- frame_current?(attrs, frame) do
      state in [:pending, :served, :active]
    else
      _ -> false
    end
  end

  def preload_frame?(_attrs), do: false

  def terminal_frame?(attrs, event_type) when is_map(attrs) and is_binary(event_type) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [{{:sandbox_frame, ^key}, %{frame_generation: ^frame_generation} = frame}] <-
           :ets.lookup(@table, {:sandbox_frame, key}) do
      terminal_frame_accepts?(frame, event_type)
    else
      _ -> false
    end
  end

  def terminal_frame?(_attrs, _event_type), do: false

  def terminate_frame?(attrs, event_type) when is_map(attrs) and is_binary(event_type) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [{{:sandbox_frame, ^key}, %{frame_generation: ^frame_generation} = frame}] <-
           :ets.lookup(@table, {:sandbox_frame, key}),
         true <- terminal_frame_accepts?(frame, event_type) do
      terminal_events =
        frame
        |> Map.get(:terminal_events, [])
        |> then(&[event_type | Enum.reject(&1, fn type -> type == event_type end)])

      insert_frame_marker(attrs, :terminal, @terminal_frame_ttl_ms, terminal_events)

      true
    else
      _ -> false
    end
  end

  def terminate_frame?(_attrs, _event_type), do: false

  def revoke_frame(attrs) when is_map(attrs) do
    case frame_key(attrs) do
      {:ok, key} -> :ets.delete(@table, {:sandbox_frame, key})
      :error -> :ok
    end

    maybe_revoke_primary_frame(attrs)
    :ok
  end

  def revoke_frame(_attrs), do: :ok

  def current_frame?(attrs) when is_map(attrs) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [
           {{:sandbox_frame, ^key},
            %{frame_generation: ^frame_generation, state: :active} = frame}
         ] <-
           :ets.lookup(@table, {:sandbox_frame, key}),
         true <- frame_current?(attrs, frame) do
      true
    else
      _ -> false
    end
  end

  def current_frame?(_attrs), do: false

  def cleanup_frame?(attrs) when is_map(attrs) do
    with frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, key} <- frame_key(attrs),
         [
           {{:sandbox_frame, ^key}, %{frame_generation: ^frame_generation, state: state}}
         ] <-
           :ets.lookup(@table, {:sandbox_frame, key}) do
      state in [:active, :terminal]
    else
      _ -> false
    end
  end

  def cleanup_frame?(_attrs), do: false

  def consume(id, expected) when is_binary(id) do
    now = System.system_time(:millisecond)

    case :ets.take(@table, id) do
      [{^id, %{expires_at_ms: expires_at_ms} = session}] when expires_at_ms >= now ->
        if matches_expected?(session, expected) do
          {:ok, session}
        else
          {:error, :plugin_sandbox_document_session_mismatch}
        end

      [{^id, _expired}] ->
        {:error, :plugin_sandbox_document_session_expired}

      [] ->
        {:error, :plugin_sandbox_document_session_not_found}
    end
  end

  def consume(_id, _expected), do: {:error, :plugin_sandbox_document_session_not_found}

  @impl true
  def init(_opts) do
    table =
      :ets.new(@table, [
        :set,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

    schedule_cleanup()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    now = System.system_time(:millisecond)

    :ets.select_delete(@table, [
      {{:_, %{expires_at_ms: :"$1"}}, [{:<, :"$1", now}], [true]}
    ])

    schedule_cleanup()
    {:noreply, state}
  end

  defp matches_expected?(session, expected) do
    Enum.all?(expected, fn {key, value} -> Map.get(session, key) == value end)
  end

  defp frame_key!(attrs) do
    {:ok, key} = frame_key(attrs)
    key
  end

  defp frame_key(attrs) do
    with {:ok, owner_key} <- frame_owner_key(attrs),
         frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation) do
      {:ok, {owner_key, frame_generation}}
    else
      _ -> :error
    end
  end

  defp frame_owner_key(attrs) do
    values = Enum.map(@frame_owner_key_fields, &Map.get(attrs, &1))

    if Enum.all?(values, &(not is_nil(&1))) do
      {:ok, List.to_tuple(values)}
    else
      :error
    end
  end

  defp frame_scope(attrs) do
    case Map.get(attrs, :sandbox_document_frame_scope, :primary) do
      "secondary" -> :secondary
      :secondary -> :secondary
      _ -> :primary
    end
  end

  defp insert_frame_marker(
         attrs,
         state,
         ttl_ms,
         terminal_events \\ [],
         primary_update \\ :refresh_primary
       ) do
    marker = frame_marker(attrs, state, ttl_ms, terminal_events)
    true = :ets.insert(@table, {{:sandbox_frame, frame_key!(attrs)}, marker})
    maybe_mark_primary_frame(attrs, marker, primary_update)
    :ok
  end

  defp maybe_mark_primary_frame(attrs, marker, primary_update) do
    if frame_scope(attrs) == :primary do
      {:ok, owner_key} = frame_owner_key(attrs)

      if primary_update == :replace_primary or
           current_primary_generation(owner_key) == marker.frame_generation do
        true =
          :ets.insert(
            @table,
            {{:current_primary_frame, owner_key},
             %{
               frame_generation: marker.frame_generation,
               expires_at_ms: marker.expires_at_ms
             }}
          )
      end
    end

    :ok
  end

  defp current_primary_generation(owner_key) do
    case :ets.lookup(@table, {:current_primary_frame, owner_key}) do
      [{{:current_primary_frame, ^owner_key}, %{frame_generation: frame_generation}}] ->
        frame_generation

      _ ->
        nil
    end
  end

  defp maybe_revoke_primary_frame(attrs) do
    with true <- frame_scope(attrs) == :primary,
         frame_generation when is_integer(frame_generation) and frame_generation > 0 <-
           Map.get(attrs, :frame_generation),
         {:ok, owner_key} <- frame_owner_key(attrs),
         [{{:current_primary_frame, ^owner_key}, %{frame_generation: ^frame_generation}}] <-
           :ets.lookup(@table, {:current_primary_frame, owner_key}) do
      :ets.delete(@table, {:current_primary_frame, owner_key})
    else
      _ -> :ok
    end
  end

  defp frame_current?(attrs, frame) do
    case Map.get(frame, :scope, frame_scope(attrs)) do
      :primary -> primary_frame_current?(attrs, frame)
      _ -> true
    end
  end

  defp primary_frame_current?(attrs, frame) do
    with {:ok, owner_key} <- frame_owner_key(attrs),
         [{{:current_primary_frame, ^owner_key}, %{frame_generation: generation}}] <-
           :ets.lookup(@table, {:current_primary_frame, owner_key}) do
      generation == frame.frame_generation
    else
      _ -> false
    end
  end

  defp terminal_frame_accepts?(%{state: state}, _event_type)
       when state in [:pending, :served, :active],
       do: true

  defp terminal_frame_accepts?(%{state: :terminal}, _event_type), do: true

  defp terminal_frame_accepts?(_frame, _event_type), do: false

  defp frame_marker(attrs, state, ttl_ms, terminal_events) do
    %{
      frame_generation: Map.fetch!(attrs, :frame_generation),
      scope: frame_scope(attrs),
      state: state,
      expires_at_ms: System.system_time(:millisecond) + ttl_ms,
      terminal_events: terminal_events
    }
  end

  defp random_token(byte_count) do
    byte_count
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end
end
