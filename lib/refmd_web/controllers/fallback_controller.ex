defmodule RefMDWeb.FallbackController do
  use RefMDWeb, :controller

  @index_path Path.join(:code.priv_dir(:refmd), "static/index.html")

  def index(conn, _params) do
    if String.starts_with?(conn.request_path, "/assets/") do
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(:not_found, "Not Found")
    else
      send_index(conn)
    end
  end

  defp send_index(conn) do
    case File.read(@index_path) do
      {:ok, html} ->
        html = inject_csp_nonce(html, conn.private[:csp_nonce])

        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_content_type("text/html")
        |> send_resp(200, html)

      _ ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "not_found"})
    end
  end

  defp inject_csp_nonce(html, nil), do: html

  defp inject_csp_nonce(html, nonce) do
    meta = ~s(<meta name="csp-nonce" content="#{nonce}">)

    html
    |> String.replace("</head>", "#{meta}\n  </head>", global: false)
    |> String.replace(~r/<link\s+rel="stylesheet"/, ~s(<link rel="stylesheet" nonce="#{nonce}"))
    |> String.replace(~r/<style\b/, ~s(<style nonce="#{nonce}"))
  end
end
