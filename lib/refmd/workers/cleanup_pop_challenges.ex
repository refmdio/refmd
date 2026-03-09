defmodule RefMD.Workers.CleanupPopChallenges do
  @moduledoc """
  Periodic cleanup of expired PoP challenges, recovery challenges,
  pending devices, and trust transfer nonces.
  """

  use Oban.Worker, queue: :default

  @impl Oban.Worker
  def perform(_job) do
    {pop_count, _} = RefMD.Accounts.delete_expired_pop_challenges()
    {recovery_count, _} = RefMD.Accounts.delete_expired_recovery_challenges()
    {pending_count, _} = RefMD.Accounts.delete_expired_pending_devices()
    {nonce_count, _} = RefMD.Accounts.delete_expired_trust_transfer_nonces()

    total = pop_count + recovery_count + pending_count + nonce_count

    if total > 0 do
      require Logger

      Logger.info(
        "Cleanup: #{pop_count} pop challenges, #{recovery_count} recovery challenges, " <>
          "#{pending_count} pending devices, #{nonce_count} trust transfer nonces"
      )
    end

    :ok
  end
end
