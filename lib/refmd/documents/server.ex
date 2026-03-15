defmodule RefMD.Documents.Server do
  @moduledoc """
  GenServer per document managing in-memory state for real-time collaboration.
  Caches active snapshot state and tracks connected Channel PIDs.
  """

  use GenServer, restart: :transient

  alias RefMD.Documents

  @dialyzer {:no_opaque,
             [schedule_idle_timeout: 1, cancel_idle_timeout: 1, maybe_schedule_idle_timeout: 1]}

  @idle_timeout :timer.minutes(30)

  defstruct [
    :document_id,
    :active_snapshot_id,
    :clocks,
    :idle_timer_ref,
    connections: MapSet.new()
  ]

  @type t :: %__MODULE__{
          document_id: String.t(),
          active_snapshot_id: String.t() | nil,
          clocks: map(),
          idle_timer_ref: reference() | nil,
          connections: MapSet.t(pid())
        }

  # ── Public API ──────────────────────────────────

  @spec get_or_start(String.t()) :: {:ok, pid()} | {:error, term()}
  def get_or_start(document_id) do
    case Registry.lookup(RefMD.Documents.Registry, document_id) do
      [{pid, _}] ->
        {:ok, pid}

      [] ->
        case DynamicSupervisor.start_child(
               RefMD.Documents.Supervisor,
               {__MODULE__, document_id}
             ) do
          {:ok, pid} -> {:ok, pid}
          {:error, {:already_started, pid}} -> {:ok, pid}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @spec register_connection(String.t(), pid()) :: :ok
  def register_connection(document_id, channel_pid) do
    GenServer.call(via(document_id), {:register_connection, channel_pid})
  end

  @spec unregister_connection(String.t(), pid()) :: :ok
  def unregister_connection(document_id, channel_pid) do
    GenServer.cast(via(document_id), {:unregister_connection, channel_pid})
  end

  @spec get_state(String.t()) :: {String.t() | nil, map()}
  def get_state(document_id) do
    GenServer.call(via(document_id), :get_state)
  end

  @spec update_clocks(String.t(), String.t(), integer()) :: :ok
  def update_clocks(document_id, device_signing_pub_key, clock) do
    GenServer.cast(via(document_id), {:update_clocks, device_signing_pub_key, clock})
  end

  @spec set_active_snapshot(String.t(), String.t(), map()) :: :ok
  def set_active_snapshot(document_id, snapshot_id, clocks) do
    GenServer.cast(via(document_id), {:set_active_snapshot, snapshot_id, clocks})
  end

  # ── GenServer Callbacks ─────────────────────────

  @spec start_link(String.t()) :: GenServer.on_start()
  def start_link(document_id) do
    GenServer.start_link(__MODULE__, document_id, name: via(document_id))
  end

  @impl true
  def init(document_id) do
    state = load_from_db(document_id)
    {:ok, schedule_idle_timeout(state)}
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

  @impl true
  def handle_cast({:update_clocks, device_signing_pub_key, clock}, state) do
    clocks = Map.put(state.clocks, device_signing_pub_key, clock)
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

  defp via(document_id) do
    {:via, Registry, {RefMD.Documents.Registry, document_id}}
  end

  defp schedule_idle_timeout(state) do
    ref = Process.send_after(self(), :idle_timeout, @idle_timeout)
    %{state | idle_timer_ref: ref}
  end

  defp cancel_idle_timeout(%{idle_timer_ref: nil} = state), do: state

  defp cancel_idle_timeout(%{idle_timer_ref: ref} = state) do
    Process.cancel_timer(ref)
    %{state | idle_timer_ref: nil}
  end

  defp maybe_schedule_idle_timeout(%{idle_timer_ref: ref} = state) when ref != nil, do: state

  defp maybe_schedule_idle_timeout(state) do
    if MapSet.size(state.connections) == 0 do
      schedule_idle_timeout(state)
    else
      state
    end
  end
end
