defmodule RefMDWeb.PublicPageController do
  use RefMDWeb, :controller

  alias RefMD.Public

  @index_path Path.join(:code.priv_dir(:refmd), "static/index.html")

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"author_slug" => author_slug, "document_slug" => document_slug}) do
    case Public.resolve_public_document(author_slug, document_slug) do
      {:ok, public_document} ->
        render_public_html(conn, public_document)

      {:error, :not_found} ->
        send_resp(conn, :not_found, "Not Found")
    end
  end

  @spec show_author(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show_author(conn, %{"author_slug" => author_slug}) do
    case Public.list_author_documents(author_slug) do
      {:ok, author_page} -> render_author_html(conn, author_page)
      {:error, :not_found} -> send_resp(conn, :not_found, "Not Found")
    end
  end

  defp render_author_html(conn, author_page) do
    case File.read(@index_path) do
      {:ok, html} ->
        html =
          html
          |> inject_author_metadata(conn, author_page)
          |> inject_csp_nonce(conn.private[:csp_nonce])

        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_content_type("text/html")
        |> send_resp(200, html)

      _ ->
        send_resp(conn, :not_found, "Not Found")
    end
  end

  defp render_public_html(conn, public_document) do
    case File.read(@index_path) do
      {:ok, html} ->
        html =
          html
          |> inject_public_metadata(conn, public_document)
          |> inject_csp_nonce(conn.private[:csp_nonce])

        conn
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_content_type("text/html")
        |> send_resp(200, html)

      _ ->
        send_resp(conn, :not_found, "Not Found")
    end
  end

  defp inject_public_metadata(html, conn, public_document) do
    tags = public_metadata_tags(conn, public_document)

    html
    |> String.replace(~r/<title>.*?<\/title>/, "<title>#{escape(public_document.title)}</title>",
      global: false
    )
    |> String.replace("</head>", tags <> "\n  </head>", global: false)
  end

  defp inject_author_metadata(html, conn, author_page) do
    tags = author_metadata_tags(conn, author_page)
    title = escape(author_page.author_name)

    html
    |> String.replace(~r/<title>.*?<\/title>/, "<title>#{title}</title>", global: false)
    |> String.replace("</head>", tags <> "\n  </head>", global: false)
  end

  defp author_metadata_tags(conn, author_page) do
    title = escape(author_page.author_name)
    description = escape(author_page.author_description || "")
    url = escape(author_url(conn, author_page))

    """
    <meta property="og:title" content="#{title}">
    <meta property="og:description" content="#{description}">
    <meta property="og:type" content="profile">
    <meta property="og:url" content="#{url}">
    <meta property="og:image" content="/og-default.png">
    <meta name="twitter:card" content="summary_large_image">
    """
  end

  defp public_metadata_tags(conn, public_document) do
    title = escape(public_document.title)
    description = public_document.content |> markdown_summary() |> escape()
    url = escape(public_url(conn, public_document))

    robots =
      if public_document.noindex, do: ~s(\n    <meta name="robots" content="noindex">), else: ""

    """
    <meta property="og:title" content="#{title}">
    <meta property="og:description" content="#{description}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="#{url}">
    <meta property="og:image" content="/og-default.png">
    <meta name="twitter:card" content="summary_large_image">#{robots}
    """
  end

  defp public_url(conn, public_document) do
    scheme = conn.scheme |> Atom.to_string()
    host = conn.host
    port = if conn.port in [80, 443], do: "", else: ":#{conn.port}"
    "#{scheme}://#{host}#{port}/@#{public_document.author_slug}/#{public_document.slug}"
  end

  defp author_url(conn, author_page) do
    scheme = conn.scheme |> Atom.to_string()
    host = conn.host
    port = if conn.port in [80, 443], do: "", else: ":#{conn.port}"
    "#{scheme}://#{host}#{port}/@#{author_page.author_slug}"
  end

  defp markdown_summary(content) do
    content
    |> String.replace(~r/```.*?```/s, " ")
    |> String.replace(~r/`([^`]*)`/, "\\1")
    |> String.replace(~r/!\[([^\]]*)\]\([^)]+\)/, "\\1")
    |> String.replace(~r/\[([^\]]+)\]\([^)]+\)/, "\\1")
    |> String.replace(~r/[#>*_\-\[\]()`]/, " ")
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
    |> String.slice(0, 160)
  end

  defp inject_csp_nonce(html, nil), do: html

  defp inject_csp_nonce(html, nonce) do
    meta = ~s(<meta name="csp-nonce" content="#{escape(nonce)}">)

    html
    |> String.replace("</head>", "#{meta}\n  </head>", global: false)
    |> String.replace(
      ~r/<link\s+rel="stylesheet"/,
      ~s(<link rel="stylesheet" nonce="#{escape(nonce)}")
    )
    |> String.replace(~r/<style\b/, ~s(<style nonce="#{escape(nonce)}"))
  end

  defp escape(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
  end
end
