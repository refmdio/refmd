defmodule RefMDWeb.Plugs.RateLimit.Storage do
  @moduledoc """
  ETS-backed storage for rate limit counters with periodic cleanup.
  """

  use GenServer

  @clean_interval_ms 60_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    table =
      :ets.new(RefMDWeb.Plugs.RateLimit.Storage, [
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
    current_window = div(now, @clean_interval_ms)

    :ets.select_delete(RefMDWeb.Plugs.RateLimit.Storage, [
      {{{:_, :"$1"}, :_}, [{:<, :"$1", current_window - 1}], [true]}
    ])

    schedule_cleanup()
    {:noreply, state}
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @clean_interval_ms)
  end
end
