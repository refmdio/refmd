defmodule RefMD.Workers.CleanupPluginPackageStorage do
  @moduledoc """
  Periodic cleanup of inactive plugin package storage objects.
  """

  use Oban.Worker, queue: :default

  alias RefMD.Plugins

  require Logger

  @impl Oban.Worker
  def perform(_job) do
    case Plugins.cleanup_package_storage() do
      {:ok, stats} ->
        log_cleanup(stats)
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp log_cleanup(stats) do
    deleted = stats.pending_deleted + stats.scanned_deleted

    if deleted > 0 or stats.failed > 0 do
      Logger.info(
        "Cleanup: #{deleted} plugin package storage objects, " <>
          "#{stats.protected} protected, #{stats.failed} failed"
      )
    end
  end
end
