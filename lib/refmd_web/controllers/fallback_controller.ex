defmodule RefMDWeb.FallbackController do
  use RefMDWeb, :controller

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    index_path = Path.join(:code.priv_dir(:refmd), "static/index.html")

    if File.exists?(index_path) do
      conn
      |> put_resp_content_type("text/html")
      |> send_file(200, index_path)
    else
      conn
      |> put_status(:not_found)
      |> json(%{error: "not_found"})
    end
  end
end
