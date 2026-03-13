defmodule RefMDWeb.HealthController do
  use RefMDWeb, :controller

  alias RefMD.Repo

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    db_status = check_database()
    cluster_nodes = Node.list([:this, :visible])

    status =
      cond do
        db_status != "connected" -> "unhealthy"
        length(cluster_nodes) < expected_cluster_size() -> "degraded"
        true -> "healthy"
      end

    json(conn, %{
      status: status,
      database: db_status,
      cluster_nodes: Enum.map(cluster_nodes, &Atom.to_string/1)
    })
  end

  defp check_database do
    case Repo.query("SELECT 1") do
      {:ok, _} -> "connected"
      {:error, _} -> "disconnected"
    end
  end

  defp expected_cluster_size do
    Application.get_env(:refmd, :expected_cluster_size, 1)
  end
end
