defmodule RefMDWeb.Plugs.ResolveDocumentWorkspace do
  @moduledoc """
  Plug that resolves workspace_id from a document_id path parameter.

  Loads the document by ID, assigns it to conn.assigns.document,
  and sets conn.assigns.workspace_id for downstream RequireRBAC usage.

  Returns 404 if the document is not found or the document_id is invalid.
  """

  import Plug.Conn

  alias RefMD.Documents

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    document_id = conn.path_params["document_id"]

    if Regex.match?(@uuid_regex, document_id || "") do
      case Documents.get_document(document_id) do
        nil ->
          conn
          |> put_status(:not_found)
          |> Phoenix.Controller.json(%{error: "document_not_found"})
          |> halt()

        document ->
          conn
          |> assign(:document, document)
          |> assign(:workspace_id, document.workspace_id)
      end
    else
      conn
      |> put_status(:bad_request)
      |> Phoenix.Controller.json(%{error: "invalid_document_id"})
      |> halt()
    end
  end
end
