defmodule RefMDWeb.PublicDocumentController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Public
  alias RefMDWeb.Channels.Document.Access
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace when action not in [:show_public, :show_author]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:admin"]
       when action in [:create, :show, :update, :delete]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:write"]
       when action in [:update_content]

  operation(:create,
    summary: "Publish a document",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    request_body: {"Publication params", "application/json", Schemas.CreatePublicationRequest},
    responses: [
      created: {"Publication", "application/json", Schemas.PublicationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.PublicationConflictResponse},
      request_entity_too_large: {"Too large", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, %{"document_id" => document_id} = params) do
    attrs = Map.take(params, ["slug", "title", "content", "content_hash", "noindex"])

    case Public.create_publication(document_id, conn.assigns.current_user_id, attrs) do
      {:ok, response} ->
        conn |> put_status(:created) |> json(response)

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:show,
    summary: "Get publication settings",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Publication", "application/json", Schemas.PublicationResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"document_id" => document_id}) do
    case Public.get_publication(document_id) do
      {:ok, response} -> json(conn, response)
      {:error, reason} -> handle_error(conn, reason)
    end
  end

  operation(:update,
    summary: "Update publication settings",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    request_body: {"Publication settings", "application/json", Schemas.UpdatePublicationRequest},
    responses: [
      ok: {"Publication", "application/json", Schemas.PublicationResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.PublicationConflictResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update(conn, %{"document_id" => document_id} = params) do
    attrs = Map.take(params, ["slug", "noindex"])

    case Public.update_publication(document_id, attrs) do
      {:ok, response} -> json(conn, response)
      {:error, reason} -> handle_error(conn, reason)
    end
  end

  operation(:delete,
    summary: "Unpublish a document",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    responses: [
      no_content: {"Deleted", "application/json", nil},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"document_id" => document_id}) do
    case Public.delete_publication(document_id) do
      :ok -> send_resp(conn, :no_content, "")
      {:error, reason} -> handle_error(conn, reason)
    end
  end

  operation(:update_content,
    summary: "Sync publication content",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Publication content", "application/json", Schemas.UpdatePublicationContentRequest},
    responses: [
      ok: {"Content sync result", "application/json", Schemas.PublicationContentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      request_entity_too_large: {"Too large", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update_content(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update_content(conn, %{"document_id" => document_id} = params) do
    attrs = Map.take(params, ["title", "content", "content_hash"])

    if Access.publication_sync_allowed?(
         conn.assigns.document,
         conn.assigns.current_user_id,
         nil,
         nil
       ) do
      case Public.update_publication_content(document_id, attrs) do
        {:ok, response} -> json(conn, response)
        {:error, reason} -> handle_error(conn, reason)
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})
    end
  end

  operation(:show_public,
    summary: "Get a public document",
    parameters: [
      author_slug: [in: :path, type: :string, required: true],
      document_slug: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Public document", "application/json", Schemas.PublicDocumentResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      gone: {"Gone", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show_public(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show_public(conn, %{"author_slug" => author_slug, "document_slug" => document_slug}) do
    case Public.resolve_public_document(author_slug, document_slug) do
      {:ok, response} ->
        json(conn, Map.delete(response, :document_id))

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:show_author,
    summary: "Get a public author page",
    parameters: [author_slug: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Public author", "application/json", Schemas.PublicAuthorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show_author(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show_author(conn, %{"author_slug" => author_slug}) do
    case Public.list_author_documents(author_slug) do
      {:ok, response} -> json(conn, response)
      {:error, :not_found} -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  defp handle_error(conn, :not_found),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp handle_error(conn, :already_published) do
    conn |> put_status(:conflict) |> json(%{error: "already_published"})
  end

  defp handle_error(conn, :public_publishing_disabled) do
    conn |> put_status(:forbidden) |> json(%{error: "public_publishing_disabled"})
  end

  defp handle_error(conn, :public_author_profile_required) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "public_author_profile_required"})
  end

  defp handle_error(conn, {:slug_conflict, suggested_slug}) do
    conn
    |> put_status(:conflict)
    |> json(%{error: "slug_conflict", suggested_slug: suggested_slug})
  end

  defp handle_error(conn, :content_too_large) do
    conn |> put_status(:request_entity_too_large) |> json(%{error: "content_too_large"})
  end

  defp handle_error(conn, reason) when reason in [:invalid_hash, :invalid_slug, :invalid_value] do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
  end

  defp handle_error(conn, %Ecto.Changeset{} = changeset) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "validation_error", details: validation_errors(changeset)})
  end

  defp validation_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end
end
