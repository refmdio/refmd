defmodule RefMD.Workers.RetryRotationMarking do
  @moduledoc """
  Retries KEK/DEK rotation marking after a best-effort failure during member removal.
  """

  use Oban.Worker, queue: :default, max_attempts: 5

  import Ecto.Query
  alias RefMD.Repo
  alias RefMD.Workspaces
  alias RefMD.Workspaces.Workspace

  @impl Oban.Worker
  def perform(%Oban.Job{
        args: %{"workspace_id" => workspace_id, "initiator_user_id" => initiator_user_id}
      }) do
    from(w in Workspace,
      where: w.id == ^workspace_id and w.needs_kek_rotation == false
    )
    |> Repo.update_all(
      set: [
        needs_kek_rotation: true,
        kek_rotation_initiator_user_id: initiator_user_id
      ]
    )

    Workspaces.mark_dek_rotation_needed([workspace_id])

    :ok
  end
end
