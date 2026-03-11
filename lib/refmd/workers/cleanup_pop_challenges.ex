defmodule RefMD.Workers.CleanupPopChallenges do
  @moduledoc """
  Periodic cleanup of expired PoP challenges, recovery challenges,
  device registrations, and trust transfer nonces.
  """

  use Oban.Worker, queue: :default

  @impl Oban.Worker
  def perform(_job) do
    {pop_count, _} = RefMD.Auth.delete_expired_pop_challenges()
    {recovery_count, _} = RefMD.Auth.delete_expired_recovery_challenges()
    {pending_count, _} = RefMD.Devices.delete_expired_device_registrations()
    {nonce_count, _} = RefMD.Auth.delete_expired_trust_transfer_nonces()

    total = pop_count + recovery_count + pending_count + nonce_count

    if total > 0 do
      require Logger

      Logger.info(
        "Cleanup: #{pop_count} pop challenges, #{recovery_count} recovery challenges, " <>
          "#{pending_count} device registrations, #{nonce_count} trust transfer nonces"
      )
    end

    :ok
  end
end
