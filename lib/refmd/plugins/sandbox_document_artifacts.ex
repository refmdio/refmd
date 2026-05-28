defmodule RefMD.Plugins.SandboxDocumentArtifacts do
  @moduledoc false

  use GenServer

  @table __MODULE__
  @max_entries 12
  @max_total_bytes 48_000_000
  @ttl_ms 15 * 60 * 1000
  @cleanup_interval_ms 60_000

  @type key :: term()
  @type artifact :: map()

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec get(key()) :: {:ok, artifact()} | :miss
  def get(key) do
    case table() do
      :undefined ->
        :miss

      table ->
        now = System.system_time(:millisecond)

        case :ets.lookup(table, key) do
          [{^key, %{expires_at_ms: expires_at_ms, artifact: artifact} = entry}]
          when expires_at_ms > now ->
            :ets.update_element(table, key, {2, %{entry | last_used_at_ms: now}})
            {:ok, artifact}

          [{^key, _expired}] ->
            :ets.delete(table, key)
            :miss

          [] ->
            :miss
        end
    end
  end

  @spec put(key(), artifact(), non_neg_integer()) :: :ok
  def put(key, artifact, bytes) when is_integer(bytes) and bytes >= 0 do
    case table() do
      :undefined ->
        :ok

      table ->
        now = System.system_time(:millisecond)

        :ets.insert(table, {
          key,
          %{
            artifact: artifact,
            bytes: bytes,
            last_used_at_ms: now,
            expires_at_ms: now + @ttl_ms
          }
        })

        GenServer.cast(__MODULE__, :trim)
        :ok
    end
  end

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
  def handle_cast(:trim, state) do
    trim(state.table)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    trim(state.table)
    schedule_cleanup()
    {:noreply, state}
  end

  defp table do
    if Process.whereis(__MODULE__), do: @table, else: :undefined
  end

  defp trim(table) do
    now = System.system_time(:millisecond)

    entries =
      table
      |> :ets.tab2list()
      |> Enum.reject(fn {key, entry} ->
        if entry.expires_at_ms <= now do
          :ets.delete(table, key)
          true
        else
          false
        end
      end)
      |> Enum.sort_by(fn {_key, entry} -> entry.last_used_at_ms end)

    trim_to_limits(table, entries, total_bytes(entries))
  end

  defp trim_to_limits(_table, entries, total_bytes)
       when length(entries) <= @max_entries and total_bytes <= @max_total_bytes,
       do: :ok

  defp trim_to_limits(table, [{key, entry} | rest], total_bytes) do
    :ets.delete(table, key)
    trim_to_limits(table, rest, total_bytes - entry.bytes)
  end

  defp trim_to_limits(_table, [], _total_bytes), do: :ok

  defp total_bytes(entries) do
    Enum.reduce(entries, 0, fn {_key, entry}, total -> total + entry.bytes end)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end
end
