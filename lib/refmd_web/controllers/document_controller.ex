defmodule RefMDWeb.DocumentController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Documents
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:read"] when action in [:index]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:write"] when action in [:create, :reorder]

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace
       when action in [:show, :update, :delete, :archive, :unarchive]

  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:read"] when action in [:show]
  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:write"] when action in [:update]
  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:delete"] when action in [:delete]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:archive"] when action in [:archive, :unarchive]

  # ── GET /api/documents?workspace_id=... ─────────

  operation(:index,
    summary: "List documents in a workspace",
    parameters: [
      workspace_id: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Document list", "application/json", Schemas.DocumentsListResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    workspace_id = conn.assigns.workspace_id
    documents = Documents.list_documents(workspace_id)

    json(conn, %{
      documents: Enum.map(documents, &serialize_document/1)
    })
  end

  # ── POST /api/documents ─────────────────────────

  operation(:create,
    summary: "Create a document or folder",
    request_body: {"Document params", "application/json", Schemas.CreateDocumentRequest},
    responses: [
      created: {"Created document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, %{"workspace_id" => workspace_id, "doc_type" => _doc_type} = params) do
    attrs =
      params
      |> Map.take([
        "id",
        "doc_type",
        "parent_id",
        "title",
        "encrypted_title",
        "encrypted_title_nonce",
        "encrypted_title_key_version"
      ])
      |> Map.put("workspace_id", workspace_id)
      |> Map.put("created_by", conn.assigns.current_user_id)

    case decode_binary_fields(attrs) do
      {:ok, decoded_attrs} ->
        case Documents.create_document(decoded_attrs) do
          {:ok, document} ->
            conn
            |> put_status(:created)
            |> json(serialize_document(document))

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "validation_error", details: format_errors(changeset)})
        end

      {:error, field} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: %{field => ["invalid base64url encoding"]}})
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "validation_error", details: %{base: ["missing required fields"]}})
  end

  # ── GET /api/documents/:document_id ─────────────

  operation(:show,
    summary: "Get document details",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Document details", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    json(conn, serialize_document(conn.assigns.document))
  end

  # ── PATCH /api/documents/:document_id ───────────

  operation(:update,
    summary: "Update a document",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Update params", "application/json", Schemas.UpdateDocumentRequest},
    responses: [
      ok: {"Updated document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update(conn, params) do
    document = conn.assigns.document

    raw_attrs =
      params
      |> Map.take([
        "title",
        "parent_id",
        "encrypted_title",
        "encrypted_title_nonce",
        "encrypted_title_key_version"
      ])

    case decode_binary_fields(raw_attrs) do
      {:ok, attrs} ->
        case Documents.update_document(document, attrs) do
          {:ok, updated} ->
            json(conn, serialize_document(updated))

          {:error, :document_archived} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "document_archived"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "validation_error", details: format_errors(changeset)})
        end

      {:error, field} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: %{field => ["invalid base64url encoding"]}})
    end
  end

  # ── DELETE /api/documents/:document_id ──────────

  operation(:delete,
    summary: "Delete a document permanently",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Deleted", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Cannot delete", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, _params) do
    document = conn.assigns.document

    case Documents.delete_document(document) do
      {:ok, _} ->
        json(conn, %{ok: true})

      {:error, :folder_not_empty} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "folder_not_empty"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "delete_failed", details: format_errors(changeset)})
    end
  end

  # ── POST /api/documents/:document_id/archive ────

  operation(:archive,
    summary: "Archive a document recursively",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Archived document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Already archived", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec archive(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def archive(conn, _params) do
    document = conn.assigns.document

    case Documents.archive_document(document) do
      {:ok, updated} ->
        json(conn, serialize_document(updated))

      {:error, :already_archived} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "already_archived"})
    end
  end

  # ── POST /api/documents/:document_id/unarchive ──

  operation(:unarchive,
    summary: "Unarchive a document recursively",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Unarchived document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity:
        {"Not archived or ancestor archived", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec unarchive(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def unarchive(conn, _params) do
    document = conn.assigns.document

    case Documents.unarchive_document(document) do
      {:ok, updated} ->
        json(conn, serialize_document(updated))

      {:error, :not_archived} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "not_archived"})

      {:error, :ancestor_archived} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "ancestor_archived"})
    end
  end

  # ── PATCH /api/documents/reorder ─────────────────

  operation(:reorder,
    summary: "Reorder a document (move and/or change position)",
    request_body: {"Reorder params", "application/json", Schemas.ReorderDocumentRequest},
    responses: [
      ok: {"Reordered document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec reorder(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def reorder(conn, params) do
    with {:ok, workspace_id} <- fetch_required_uuid(params, "workspace_id"),
         {:ok, document_id} <- fetch_required_uuid(params, "document_id"),
         {:ok, position} <- fetch_required_non_neg_integer(params, "position"),
         {:ok, new_parent_id} <- fetch_nullable_uuid(params, "parent_id") do
      case Documents.reorder_document(workspace_id, document_id, new_parent_id, position) do
        {:ok, updated} ->
          json(conn, serialize_document(updated))

        {:error, reason} when is_atom(reason) ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: to_string(reason)})
      end
    else
      {:error, field} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: %{field => ["is required"]}})
    end
  end

  # ── Helpers ─────────────────────────────────────

  defp serialize_document(document) do
    %{
      id: document.id,
      workspace_id: document.workspace_id,
      parent_id: document.parent_id,
      position: document.position,
      title: document.title,
      encrypted_title: encode_binary(document.encrypted_title),
      encrypted_title_nonce: encode_binary(document.encrypted_title_nonce),
      encrypted_title_key_version: document.encrypted_title_key_version,
      slug: document.slug,
      path: document.path,
      doc_type: document.doc_type,
      is_encrypted: document.is_encrypted,
      needs_dek_rotation: document.needs_dek_rotation,
      min_dek_version: document.min_dek_version,
      created_by: document.created_by,
      archived_at: document.archived_at,
      created_at: document.created_at,
      updated_at: document.updated_at
    }
  end

  defp decode_binary_fields(attrs) do
    with {:ok, attrs} <- decode_binary_field(attrs, "encrypted_title") do
      decode_binary_field(attrs, "encrypted_title_nonce")
    end
  end

  defp decode_binary_field(attrs, key) do
    case Map.get(attrs, key) do
      nil ->
        {:ok, attrs}

      value when is_binary(value) ->
        case Base.url_decode64(value, padding: false) do
          {:ok, decoded} -> {:ok, Map.put(attrs, key, decoded)}
          :error -> {:error, key}
        end
    end
  end

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i

  defp fetch_required(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when not is_nil(value) -> {:ok, value}
      _ -> {:error, key}
    end
  end

  defp fetch_required_uuid(params, key) do
    with {:ok, value} <- fetch_required(params, key) do
      if is_binary(value) && Regex.match?(@uuid_regex, value) do
        {:ok, value}
      else
        {:error, key}
      end
    end
  end

  defp fetch_nullable_uuid(params, key) do
    unless Map.has_key?(params, key), do: throw({:missing, key})

    case params[key] do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        if Regex.match?(@uuid_regex, value), do: {:ok, value}, else: {:error, key}

      _ ->
        {:error, key}
    end
  catch
    {:missing, field} -> {:error, field}
  end

  defp fetch_required_non_neg_integer(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when is_integer(value) and value >= 0 -> {:ok, value}
      {:ok, _} -> {:error, key}
      :error -> {:error, key}
    end
  end
end
