defmodule RefMDWeb.DocumentKeyController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Encryption
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:read"] when action in [:get_document_keys]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:write"] when action in [:create_document_key]

  operation(:get_document_keys,
    summary: "Get all DEK versions for a document",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Document keys", "application/json", Schemas.DocumentKeysResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_document_keys(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_document_keys(conn, _params) do
    document = conn.assigns.document
    keys = Encryption.list_document_encrypted_keys(document.id)

    json(conn, %{
      keys: Enum.map(keys, &format_document_key/1)
    })
  end

  operation(:create_document_key,
    summary: "Register a DEK for a document",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"DEK params", "application/json", Schemas.CreateDocumentKeyRequest},
    responses: [
      created: {"Key created", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Version already exists", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create_document_key(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_document_key(conn, params) do
    document = conn.assigns.document

    attrs = %{
      document_id: document.id,
      key_version: params["key_version"],
      kek_version: params["kek_version"],
      encrypted_dek: decode_binary!(params["encrypted_dek"]),
      nonce: decode_binary!(params["nonce"])
    }

    case Encryption.create_document_key_with_rotation(attrs) do
      {:ok, _key} ->
        conn |> put_status(:created) |> json(%{ok: true})

      {:error, :kek_version_mismatch} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "kek_version_mismatch"})

      {:error, :key_version_too_old} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "key_version_too_old"})

      {:error, :key_version_not_consecutive} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "key_version_not_consecutive"})

      {:error, :folders_cannot_have_dek} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "folders_cannot_have_dek"})

      {:error, :document_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "document_not_found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        if has_unique_constraint_error?(changeset) do
          conn |> put_status(:conflict) |> json(%{error: "key_version_already_exists"})
        else
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "invalid_key", details: format_errors(changeset)})
        end
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  defp format_document_key(key) do
    %{
      document_id: key.document_id,
      key_version: key.key_version,
      encrypted_dek: encode_binary(key.encrypted_dek),
      nonce: encode_binary(key.nonce),
      kek_version: key.kek_version,
      is_active: key.is_active,
      created_at: key.created_at
    }
  end
end
