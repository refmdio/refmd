defmodule RefMD.Workers.DeliverSecurityMutationOutbox do
  @moduledoc false

  use Oban.Worker, queue: :default, unique: [period: 30]

  alias RefMD.Security.{MutationOutbox, MutationOutboxDispatcher}

  @impl Oban.Worker
  def perform(_job) do
    MutationOutbox.process_available(&MutationOutboxDispatcher.deliver/4)
    :ok
  end
end
