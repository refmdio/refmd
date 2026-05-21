defmodule RefMDWeb.ChannelIntegrationCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL.Sandbox

  using do
    quote do
      @endpoint RefMDWeb.Endpoint

      alias RefMD.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Phoenix.ChannelTest
      import RefMD.TestCrypto
      import RefMDWeb.ChannelIntegrationCase
    end
  end

  setup _tags do
    pid = Sandbox.start_owner!(RefMD.Repo, shared: true, sandbox: false)
    on_exit(fn -> Sandbox.stop_owner(pid) end)
    :ok
  end
end
