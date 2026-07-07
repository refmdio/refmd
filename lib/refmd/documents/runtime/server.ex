defmodule RefMD.Documents.Runtime.Server do
  @moduledoc """
  GenServer per document managing in-memory state for real-time collaboration.
  Caches active snapshot state and tracks connected Channel PIDs.
  """

  use GenServer, restart: :transient

  alias RefMD.Documents

  @idle_timeout :timer.minutes(30)

  defstruct [
    :document_id,
    :active_snapshot_id,
    :clocks,
    :idle_timer_ref,
    write_sessions: %{},
    connections: MapSet.new()
  ]

  def get_or_start(document_id) do
    case Registry.lookup(RefMD.Documents.Runtime.Registry, document_id) do
      [{pid, _}] ->
        {:ok, pid}

      [] ->
        case DynamicSupervisor.start_child(
               RefMD.Documents.Runtime.Supervisor,
               {__MODULE__, document_id}
             ) do
          {:ok, pid} -> {:ok, pid}
          {:error, {:already_started, pid}} -> {:ok, pid}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  def register_connection(document_id, channel_pid) do
    GenServer.call(via(document_id), {:register_connection, channel_pid})
  end

  def unregister_connection(document_id, channel_pid) do
    GenServer.cast(via(document_id), {:unregister_connection, channel_pid})
  end

  def record_write_session(document_id, payload, expires_at_ms) do
    GenServer.call(via(document_id), {:record_write_session, payload, expires_at_ms})
  end

  def active_write_sessions(document_id) do
    GenServer.call(via(document_id), :active_write_sessions)
  end

  def get_state(document_id) do
    GenServer.call(via(document_id), :get_state)
  end

  def update_clocks(document_id, authority_context_key, signing_key_id, clock) do
    GenServer.cast(
      via(document_id),
      {:update_clocks, authority_context_key, signing_key_id, clock}
    )
  end

  def set_active_snapshot(document_id, snapshot_id, clocks) do
    GenServer.cast(via(document_id), {:set_active_snapshot, snapshot_id, clocks})
  end

  def start_link(document_id) do
    GenServer.start_link(__MODULE__, document_id, name: via(document_id))
  end

  @impl true
  def init(document_id) do
    state = load_from_db(document_id)
    ref = Process.send_after(self(), :idle_timeout, @idle_timeout)
    {:ok, %{state | idle_timer_ref: ref}}
  end

  @impl true
  def handle_call({:register_connection, channel_pid}, _from, state) do
    Process.monitor(channel_pid)

    state =
      state
      |> cancel_idle_timeout()
      |> Map.put(:connections, MapSet.put(state.connections, channel_pid))

    {:reply, :ok, state}
  end

  def handle_call(:get_state, _from, state) do
    {:reply, {state.active_snapshot_id, state.clocks}, state}
  end

  def handle_call(:active_write_sessions, _from, state) do
    state = prune_expired_write_sessions(state)

    {:reply,
     Enum.map(state.write_sessions, fn {_event_hash, {payload, _expires_at_ms}} -> payload end),
     state}
  end

  def handle_call({:record_write_session, payload, expires_at_ms}, _from, state) do
    state = prune_expired_write_sessions(state)

    event_hash =
      get_in(payload, [:publicData, "writeSessionEventHash"]) ||
        get_in(payload, ["publicData", "writeSessionEventHash"])

    state =
      if is_binary(event_hash) and is_integer(expires_at_ms) and
           expires_at_ms > System.system_time(:millisecond) do
        %{
          state
          | write_sessions: Map.put(state.write_sessions, event_hash, {payload, expires_at_ms})
        }
      else
        state
      end

    {:reply, :ok, state}
  end

  @impl true
  def handle_cast({:update_clocks, authority_context_key, signing_key_id, clock}, state) do
    clocks = Map.put(state.clocks, "#{authority_context_key}:#{signing_key_id}", clock)
    {:noreply, %{state | clocks: clocks}}
  end

  def handle_cast({:set_active_snapshot, snapshot_id, clocks}, state) do
    {:noreply, %{state | active_snapshot_id: snapshot_id, clocks: clocks}}
  end

  def handle_cast({:unregister_connection, channel_pid}, state) do
    state = %{state | connections: MapSet.delete(state.connections, channel_pid)}

    {:noreply, maybe_schedule_idle_timeout(state)}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    state = %{state | connections: MapSet.delete(state.connections, pid)}
    {:noreply, maybe_schedule_idle_timeout(state)}
  end

  def handle_info(:idle_timeout, state) do
    if MapSet.size(state.connections) == 0 do
      {:stop, :normal, state}
    else
      {:noreply, %{state | idle_timer_ref: nil}}
    end
  end

  # ── Private ─────────────────────────────────────

  defp load_from_db(document_id) do
    snapshot = Documents.get_active_snapshot(document_id)

    %__MODULE__{
      document_id: document_id,
      active_snapshot_id: snapshot && snapshot.id,
      clocks: (snapshot && snapshot.clocks) || %{}
    }
  end

  defp prune_expired_write_sessions(state) do
    now = System.system_time(:millisecond)

    write_sessions =
      state.write_sessions
      |> Enum.reject(fn {_event_hash, {_payload, expires_at_ms}} -> expires_at_ms <= now end)
      |> Map.new()

    %{state | write_sessions: write_sessions}
  end

  defp via(document_id) do
    {:via, Registry, {RefMD.Documents.Runtime.Registry, document_id}}
  end

  defp cancel_idle_timeout(%{idle_timer_ref: nil} = state), do: state

  defp cancel_idle_timeout(%{idle_timer_ref: ref} = state) do
    Process.cancel_timer(ref)
    %{state | idle_timer_ref: nil}
  end

  defp maybe_schedule_idle_timeout(%{idle_timer_ref: ref} = state) when ref != nil, do: state

  defp maybe_schedule_idle_timeout(state) do
    if MapSet.size(state.connections) == 0 do
      ref = Process.send_after(self(), :idle_timeout, @idle_timeout)
      %{state | idle_timer_ref: ref}
    else
      state
    end
  end
end
