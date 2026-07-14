defmodule RefMD.Workers.RetryRotationMarking do
  @moduledoc """
  Retries KEK/DEK rotation marking after a best-effort failure during member removal.
  """

  use Oban.Worker, queue: :default, max_attempts: 5

  alias RefMD.Workspaces

  @impl Oban.Worker
  def perform(%Oban.Job{
        args: %{"workspace_id" => workspace_id, "initiator_user_id" => initiator_user_id}
      }) do
    if Workspaces.rotation_initiator_eligible?(workspace_id, initiator_user_id) do
      Workspaces.mark_kek_rotation_needed([workspace_id], initiator_user_id)
      Workspaces.mark_dek_rotation_needed([workspace_id], "membership_change")
      :ok
    else
      {:discard, :invalid_rotation_initiator}
    end
  end
end
