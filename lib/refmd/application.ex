defmodule RefMD.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      RefMDWeb.Telemetry,
      RefMD.Repo,
      {PlugAttack.Storage.Ets, name: RefMDWeb.Plugs.RateLimit.Storage, clean_period: 60_000},
      {DNSCluster, query: Application.get_env(:refmd, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: RefMD.PubSub},
      # Start a worker by calling: RefMD.Worker.start_link(arg)
      # {RefMD.Worker, arg},
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
