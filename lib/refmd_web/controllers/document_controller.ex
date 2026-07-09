defmodule RefMDWeb.DocumentController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Crypto.Encoding
  alias RefMD.Documents
  alias RefMDWeb.Schemas

  @create_encrypted_title_fields ~w(encrypted_title encrypted_title_nonce encrypted_title_key_version)
  @encrypted_title_nonce_bytes 24

  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:read"] when action in [:index]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:write"] when action in [:create, :reorder]

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace
       when action in [
              :show,
              :update,
              :delete,
              :archive,
              :unarchive,
              :enable_read_only,
              :disable_read_only,
              :disable_writes_by_policy
            ]

  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:read"] when action in [:show]
  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:write"] when action in [:update]
  plug RefMDWeb.Plugs.RequireRBAC, [permission: "document:delete"] when action in [:delete]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:archive"]
       when action in [
              :archive,
              :unarchive,
              :enable_read_only,
              :disable_read_only,
              :disable_writes_by_policy
            ]

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

  def index(conn, _params) do
    workspace_id = conn.assigns.workspace_id

    documents =
      Documents.list_documents(workspace_id)
      |> then(
        &RefMD.Workspaces.filter_guest_documents(workspace_id, conn.assigns.current_user_id, &1)
      )

    json(conn, %{
      documents: Enum.map(documents, &serialize_document(conn, &1))
    })
  end

  # ── POST /api/documents ─────────────────────────

  operation(:create,
    summary: "Create a document or folder",
    request_body: {"Document params", "application/json", Schemas.CreateDocumentRequest},
    responses: [
      created: {"Created document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Document id already exists", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create(conn, %{"workspace_id" => workspace_id, "doc_type" => _doc_type} = params) do
    attrs =
      params
      |> Map.take([
        "id",
        "doc_type",
        "parent_id",
        "encrypted_title",
        "encrypted_title_nonce",
        "encrypted_title_key_version"
      ])
      |> Map.put("workspace_id", workspace_id)
      |> Map.put("created_by", conn.assigns.current_user_id)

    with :ok <- reject_plaintext_title_field(params),
         :ok <- require_create_encrypted_title_fields(attrs),
         {:ok, decoded_attrs} <- decode_binary_fields(attrs) do
      handle_create_result(conn, Documents.create_document(decoded_attrs))
    else
      {:error, :plaintext_title_not_allowed} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: %{"title" => ["must not be provided"]}})

      {:error, {:missing_required_fields, fields}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: required_field_errors(fields)})

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

  defp handle_create_result(conn, {:ok, document}) do
    conn
    |> put_status(:created)
    |> json(serialize_document(conn, document))
  end

  defp handle_create_result(conn, {:error, changeset}) do
    if has_constraint_error?(changeset, :id) do
      conn |> put_status(:conflict) |> json(%{error: "document_id_already_exists"})
    else
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "validation_error", details: format_errors(changeset)})
    end
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

  def show(conn, _params) do
    json(conn, serialize_document(conn, conn.assigns.document))
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

  def update(conn, params) do
    document = conn.assigns.document

    raw_attrs =
      params
      |> Map.take([
        "parent_id",
        "encrypted_title",
        "encrypted_title_nonce",
        "encrypted_title_key_version"
      ])

    with :ok <- reject_plaintext_title_field(params),
         :ok <- require_update_encrypted_title_tuple(raw_attrs) do
      handle_update_attrs(conn, document, raw_attrs)
    else
      {:error, :plaintext_title_not_allowed} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: %{"title" => ["must not be provided"]}})

      {:error, {:missing_required_fields, fields}} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: required_field_errors(fields)})
    end
  end

  defp handle_update_attrs(conn, document, raw_attrs) do
    case decode_binary_fields(raw_attrs) do
      {:ok, attrs} ->
        case Documents.update_document(document, attrs) do
          {:ok, updated} ->
            json(conn, serialize_document(conn, updated))

          {:error, :document_archived} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "document_archived"})

          {:error, :document_read_only} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "document_read_only"})

          {:error, :document_write_disabled} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "document_write_disabled"})

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
    request_body:
      {"Document write-state admission", "application/json", Schemas.DocumentWriteStateRequest},
    responses: [
      ok: {"Archived document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Already archived", "application/json", Schemas.ErrorResponse}
    ]
  )

  def archive(conn, params) do
    document = conn.assigns.document

    with {:ok, write_state_admission} <- Documents.WriteStateAdmission.parse_append(params) do
      Documents.archive_document(document, write_state_admission)
    end
    |> case do
      {:ok, updated} ->
        json(conn, serialize_document(conn, updated))

      {:error, :already_archived} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "already_archived"})

      {:error, :invalid_key_directory} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_key_directory"})
    end
  end

  # ── POST /api/documents/:document_id/unarchive ──

  operation(:unarchive,
    summary: "Unarchive a document recursively",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Document write-state admission", "application/json", Schemas.DocumentWriteStateRequest},
    responses: [
      ok: {"Unarchived document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity:
        {"Not archived or ancestor archived", "application/json", Schemas.ErrorResponse}
    ]
  )

  def unarchive(conn, params) do
    document = conn.assigns.document

    with {:ok, write_state_admission} <- Documents.WriteStateAdmission.parse_append(params) do
      Documents.unarchive_document(document, write_state_admission)
    end
    |> case do
      {:ok, updated} ->
        json(conn, serialize_document(conn, updated))

      {:error, :not_archived} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "not_archived"})

      {:error, :ancestor_archived} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "ancestor_archived"})

      {:error, :invalid_key_directory} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_key_directory"})
    end
  end

  # ── POST /api/documents/:document_id/read-only/enable

  operation(:enable_read_only,
    summary: "Mark a document read-only",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Document write-state admission", "application/json", Schemas.DocumentWriteStateRequest},
    responses: [
      ok: {"Read-only document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity:
        {"Cannot change write state", "application/json", Schemas.ErrorResponse}
    ]
  )

  def enable_read_only(conn, params) do
    handle_write_state_transition(conn, params, &Documents.enable_document_read_only/2)
  end

  # ── POST /api/documents/:document_id/read-only/disable

  operation(:disable_read_only,
    summary: "Clear document read-only state",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Document write-state admission", "application/json", Schemas.DocumentWriteStateRequest},
    responses: [
      ok: {"Writable document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity:
        {"Cannot change write state", "application/json", Schemas.ErrorResponse}
    ]
  )

  def disable_read_only(conn, params) do
    handle_write_state_transition(conn, params, &Documents.disable_document_read_only/2)
  end

  # ── POST /api/documents/:document_id/write-disable

  operation(:disable_writes_by_policy,
    summary: "Disable document writes by policy",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Document write-state admission", "application/json", Schemas.DocumentWriteStateRequest},
    responses: [
      ok: {"Write-disabled document", "application/json", Schemas.DocumentResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity:
        {"Cannot change write state", "application/json", Schemas.ErrorResponse}
    ]
  )

  def disable_writes_by_policy(conn, params) do
    handle_write_state_transition(conn, params, &Documents.disable_document_writes_by_policy/2)
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

  def reorder(conn, params) do
    with {:ok, workspace_id} <- fetch_required_uuid(params, "workspace_id"),
         {:ok, document_id} <- fetch_required_uuid(params, "document_id"),
         {:ok, position} <- fetch_required_non_neg_integer(params, "position"),
         {:ok, new_parent_id} <- fetch_optional_nullable_uuid(params, "parent_id") do
      case Documents.reorder_document(workspace_id, document_id, new_parent_id, position) do
        {:ok, updated} ->
          json(conn, serialize_document(conn, updated))

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

  defp serialize_document(conn, document) do
    %{
      id: document.id,
      workspace_id: document.workspace_id,
      parent_id: document.parent_id,
      active_snapshot_id: document.active_snapshot_id,
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
      needs_rotation_snapshot: document.needs_rotation_snapshot,
      min_dek_version: document.min_dek_version,
      is_published: RefMD.Public.published?(document.id),
      can_sync_publication:
        Documents.publication_sync_allowed?(document, conn.assigns.current_user_id, nil, nil),
      created_by: document.created_by,
      write_state: serialized_write_state(document),
      archived_at: document.archived_at,
      created_at: document.created_at,
      updated_at: document.updated_at
    }
  end

  defp handle_write_state_transition(conn, params, transition) do
    document = conn.assigns.document

    with {:ok, write_state_admission} <- Documents.WriteStateAdmission.parse_append(params) do
      transition.(document, write_state_admission)
    end
    |> case do
      {:ok, updated} ->
        json(conn, serialize_document(conn, updated))

      {:error, reason}
      when reason in [
             :already_read_only,
             :not_read_only,
             :already_write_disabled,
             :document_archived,
             :document_write_disabled,
             :invalid_key_directory,
             :invalid_write_state_transition
           ] ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  defp serialized_write_state(%{archived_at: archived_at}) when not is_nil(archived_at),
    do: "archived"

  defp serialized_write_state(%{write_state: state})
       when state in ["writable", "read_only", "archived", "write_disabled"],
       do: state

  defp serialized_write_state(_document), do: "writable"

  defp decode_binary_fields(attrs) do
    with {:ok, attrs} <- decode_binary_field(attrs, "encrypted_title") do
      decode_binary_field(attrs, "encrypted_title_nonce", @encrypted_title_nonce_bytes)
    end
  end

  defp require_create_encrypted_title_fields(attrs) do
    missing_fields =
      Enum.filter(@create_encrypted_title_fields, fn field ->
        case Map.get(attrs, field) do
          nil -> true
          "" -> true
          _value -> false
        end
      end)

    case missing_fields do
      [] -> :ok
      fields -> {:error, {:missing_required_fields, fields}}
    end
  end

  defp required_field_errors(fields) do
    Map.new(fields, &{&1, ["is required"]})
  end

  defp require_update_encrypted_title_tuple(attrs) do
    supplied_fields =
      Enum.filter(@create_encrypted_title_fields, fn field ->
        Map.has_key?(attrs, field)
      end)

    case supplied_fields do
      [] ->
        :ok

      @create_encrypted_title_fields ->
        :ok

      fields ->
        missing_fields = @create_encrypted_title_fields -- fields
        {:error, {:missing_required_fields, missing_fields}}
    end
  end

  defp reject_plaintext_title_field(params) do
    if Map.has_key?(params, "title") do
      {:error, :plaintext_title_not_allowed}
    else
      :ok
    end
  end

  defp decode_binary_field(attrs, key, expected_bytes \\ nil) do
    case Map.get(attrs, key) do
      nil ->
        {:ok, attrs}

      value when is_binary(value) ->
        {:ok, Map.put(attrs, key, Encoding.decode_base64url!(value, expected_bytes))}
    end
  rescue
    ArgumentError -> {:error, key}
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

  defp fetch_optional_nullable_uuid(params, key) do
    if Map.has_key?(params, key) do
      fetch_nullable_uuid(params, key)
    else
      {:ok, nil}
    end
  end

  defp fetch_required_non_neg_integer(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when is_integer(value) and value >= 0 -> {:ok, value}
      {:ok, _} -> {:error, key}
      :error -> {:error, key}
    end
  end

  defp has_constraint_error?(changeset, field) do
    Enum.any?(changeset.errors, fn
      {^field, {_message, opts}} -> opts[:constraint] == :unique
      _ -> false
    end)
  end
end
