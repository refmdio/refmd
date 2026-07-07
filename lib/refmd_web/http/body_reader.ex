defmodule RefMDWeb.Http.BodyReader do
  @moduledoc false

  def read_body(conn, opts) do
    case Plug.Conn.read_body(conn, opts) do
      {:ok, body, conn} -> {:ok, body, cache_body(conn, body)}
      {:more, body, conn} -> {:more, body, cache_body(conn, body)}
      {:error, _} = error -> error
    end
  end

  defp cache_body(conn, body) do
    Plug.Conn.put_private(conn, :raw_body, [conn.private[:raw_body] || "", body])
  end
end
