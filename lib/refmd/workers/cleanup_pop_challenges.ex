defmodule RefMD.Workers.CleanupPopChallenges do
  @moduledoc """
  Periodic cleanup of expired PoP challenges, recovery challenges,
  share password challenges, and device registrations.
  """

  use Oban.Worker, queue: :default

  @impl Oban.Worker
  def perform(_job) do
    {pop_count, _} = RefMD.Auth.delete_expired_pop_challenges()
    {recovery_count, _} = RefMD.Auth.delete_expired_recovery_challenges()
    {share_password_count, _} = RefMD.Sharing.delete_expired_password_challenges()
    {pending_count, _} = RefMD.Devices.delete_expired_device_registrations()

    total = pop_count + recovery_count + share_password_count + pending_count

    if total > 0 do
      require Logger

      Logger.info(
        "Cleanup: #{pop_count} pop challenges, #{recovery_count} recovery challenges, " <>
          "#{share_password_count} share password challenges, #{pending_count} device registrations"
      )
    end

    :ok
  end
end
