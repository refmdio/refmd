defmodule RefMD.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    topologies = Application.get_env(:libcluster, :topologies, [])

    :ets.new(:refmd_presence_pids, [:set, :public, :named_table])

    children = [
      RefMDWeb.Telemetry,
      RefMD.Repo,
      RefMDWeb.Plugs.RateLimit.Storage,
      {Cluster.Supervisor, [topologies, [name: RefMD.ClusterSupervisor]]},
      {Phoenix.PubSub, name: RefMD.PubSub},
      {Oban, Application.fetch_env!(:refmd, Oban)},
      {Registry, keys: :unique, name: RefMD.Documents.Runtime.Registry},
      RefMDWeb.Channels.Document.Presence,
      RefMD.Documents.Runtime.Supervisor,
      # Start to serve requests, typically the last entry
      RefMDWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: RefMD.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    RefMDWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
