defmodule RefMDWeb.DocumentShareController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Sharing, Workspaces}

  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace
       when action in [:create, :index, :verification_directory]

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace,
       [not_found_error: "not_found", invalid_error: "not_found"]
       when action in [:update, :delete, :admin_delete, :update_exclusions, :update_keys]

  plug :reject_guest_share_management when action in [:create, :index]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:manage_share"]
       when action in [:create, :index]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:read"] when action in [:verification_directory]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "workspace:admin"] when action in [:admin_delete]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:manage_share"]
       when action in [:update, :delete, :update_exclusions, :update_keys]

  defp reject_guest_share_management(conn, _opts) do
    if Workspaces.guest_user?(conn.assigns.current_user_id) do
      conn
      |> put_status(:forbidden)
      |> json(%{error: "forbidden"})
      |> halt()
    else
      conn
    end
  end

  defp derive_share_limit_cache_attrs(attrs), do: attrs

  defp encode_share_list_item(share) when is_map(share), do: share

  operation(:create,
    summary: "Create a share for a document",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Share params", "application/json", Schemas.CreateShareRequest},
    responses: [
      created: {"Created share", "application/json", Schemas.ShareCreateResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create(conn, params) do
    if Workspaces.share_links_enabled?(conn.assigns.document.workspace_id) do
      create_share_when_enabled(conn, params)
    else
      conn |> put_status(:forbidden) |> json(%{error: "share_links_disabled"})
    end
  end

  defp create_share_when_enabled(conn, params) do
    attrs =
      params
      |> Map.take([
        "id",
        "scope",
        "share_slug",
        "token_prefix",
        "authorization_public_key_material",
        "share_capability_secret_commitment",
        "password_capability_secret_commitment",
        "permission",
        "password_protected",
        "authenticated_workspace_pin_bootstrap_hash",
        "authenticated_workspace_pin_bootstrap",
        "encrypted_dek",
        "nonce",
        "share_keys",
        "exclusions",
        "salt",
        "auth_key",
        "kdf_params",
        "expires_event_sequence",
        "max_views",
        "share_link_secret_backup_wraps",
        "workspace_key_directory_events",
        "workspace_key_directory_checkpoint"
      ])
      |> derive_share_limit_cache_attrs()
      |> Map.put("actor_device_id", conn.assigns[:rrp_device_id])
      |> decode_binary_fields()

    case attrs do
      {:ok, decoded} ->
        case Sharing.create_share(conn.assigns.document, conn.assigns.current_user_id, decoded) do
          {:ok, result} ->
            conn
            |> put_status(:created)
            |> json(%{
              id: result.share.id,
              share_slug: result.share_slug,
              event_sequence: result.created_event_sequence,
              event_hash: result.share.created_event_hash
            })

          {:error, reason} ->
            handle_create_error(conn, reason)
        end

      {:error, field} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_format", field: field})
    end
  end

  operation(:index,
    summary: "List shares for a document",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Share list", "application/json", Schemas.ShareListResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def index(conn, _params) do
    shares =
      Sharing.list_document_shares(
        conn.assigns.document,
        conn.assigns.current_user_id,
        conn.assigns.workspace_role
      )

    json(conn, %{shares: Enum.map(shares, &encode_share_list_item/1)})
  end

  operation(:verification_directory,
    summary: "Get share participant verification directory for a document",
    parameters: [
      document_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Verification directory", "application/json", Schemas.ShareVerificationDirectory},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def verification_directory(conn, _params) do
    json(
      conn,
      Sharing.document_share_participant_verification_directory(conn.assigns.document.id)
    )
  end

  operation(:update,
    summary: "Update share settings",
    parameters: [
      document_id: [in: :path, type: :string, required: true],
      share_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Share update params", "application/json", Schemas.UpdateShareRequest},
    responses: [
      ok: {"Updated share", "application/json", Schemas.ShareUpdateResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update(conn, %{"share_id" => share_id} = params) do
    case validate_uuid_param(share_id, :share_id) do
      :ok ->
        attrs =
          Map.take(params, [
            "expires_event_sequence",
            "max_views",
            "workspace_key_directory_events",
            "workspace_key_directory_checkpoint"
          ])
          |> derive_share_limit_cache_attrs()

        case Sharing.update_share_settings(conn.assigns.document.id, share_id, attrs) do
          {:ok, share} ->
            json(conn, %{
              id: share.id,
              expires_event_sequence: share.expires_event_sequence,
              max_views: share.max_views,
              view_count: share.view_count
            })

          {:error, reason} ->
            handle_manage_error(conn, reason)
        end

      {:error, reason} ->
        handle_manage_error(conn, reason)
    end
  end

  operation(:delete,
    summary: "Delete a share",
    parameters: [
      document_id: [in: :path, type: :string, required: true],
      share_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Share deletion key directory", "application/json", Schemas.ShareManagementRequest,
       required: true},
    responses: [
      no_content: {"Deleted", "application/json", nil},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete(conn, %{"share_id" => share_id} = params) do
    case validate_uuid_param(share_id, :share_id) do
      :ok -> delete_valid_share(conn, share_id, params)
      {:error, reason} -> handle_manage_error(conn, reason)
    end
  end

  defp delete_valid_share(conn, share_id, params) do
    attrs =
      Map.take(params, [
        "workspace_key_directory_events",
        "workspace_key_directory_checkpoint"
      ])

    case Sharing.delete_share(conn.assigns.document.id, share_id, attrs) do
      :ok -> send_resp(conn, :no_content, "")
      {:error, reason} -> handle_manage_error(conn, reason)
    end
  end

  operation(:admin_delete,
    summary: "Delete a share as workspace admin",
    parameters: [
      document_id: [in: :path, type: :string, required: true],
      share_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Share deletion key directory", "application/json", Schemas.ShareManagementRequest,
       required: true},
    responses: [
      no_content: {"Deleted", "application/json", nil},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def admin_delete(conn, %{"share_id" => share_id} = params) do
    case validate_uuid_param(share_id, :share_id) do
      :ok -> admin_delete_valid_share(conn, share_id, params)
      {:error, reason} -> handle_manage_error(conn, reason)
    end
  end

  defp admin_delete_valid_share(conn, share_id, params) do
    attrs =
      Map.take(params, [
        "workspace_key_directory_events",
        "workspace_key_directory_checkpoint"
      ])

    case Sharing.delete_share(conn.assigns.document.id, share_id, attrs) do
      :ok -> send_resp(conn, :no_content, "")
      {:error, reason} -> handle_manage_error(conn, reason)
    end
  end

  operation(:update_exclusions,
    summary: "Update folder share exclusions",
    parameters: [
      document_id: [in: :path, type: :string, required: true],
      share_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Share exclusion update params", "application/json", Schemas.UpdateShareExclusionsRequest},
    responses: [
      ok: {"Updated exclusions", "application/json", Schemas.ShareExclusionsResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update_exclusions(conn, %{"share_id" => share_id} = params) do
    case validate_uuid_param(share_id, :share_id) do
      :ok ->
        attrs =
          Map.take(params, [
            "add",
            "remove",
            "workspace_key_directory_events",
            "workspace_key_directory_checkpoint"
          ])

        case Sharing.update_share_exclusions(
               conn.assigns.document.id,
               share_id,
               attrs
             ) do
          {:ok, result} ->
            json(conn, result)

          {:error, reason} ->
            handle_manage_error(conn, reason)
        end

      {:error, reason} ->
        handle_manage_error(conn, reason)
    end
  end

  operation(:update_keys,
    summary: "Update folder share keys",
    parameters: [
      document_id: [in: :path, type: :string, required: true],
      share_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Share key update params", "application/json", Schemas.UpdateShareKeysRequest,
       required: true},
    responses: [
      ok: {"Updated share keys", "application/json", Schemas.ShareKeysUpdateResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def update_keys(conn, %{"share_id" => share_id} = params) do
    with :ok <- validate_uuid_param(share_id, :share_id),
         {:ok, attrs} <-
           decode_share_key_update_params(
             Map.take(params, [
               "add_keys",
               "replace_keys",
               "workspace_key_directory_events",
               "workspace_key_directory_checkpoint"
             ])
           ) do
      case Sharing.update_share_keys(conn.assigns.document.id, share_id, attrs) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          handle_manage_error(conn, reason)
      end
    else
      {:error, {:invalid_format, field}} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_format", field: field})

      {:error, reason} ->
        handle_manage_error(conn, reason)
    end
  end

  defp decode_binary_fields(attrs) do
    with {:ok, encrypted_dek} <-
           decode_required_binary_field(attrs["encrypted_dek"], "encrypted_dek"),
         {:ok, nonce} <- decode_optional_binary_field(attrs["nonce"], "nonce"),
         {:ok, share_keys} <- decode_share_keys(attrs["share_keys"]),
         {:ok, salt} <- decode_optional_binary_field(attrs["salt"], "salt"),
         {:ok, auth_key} <- decode_optional_binary_field(attrs["auth_key"], "auth_key") do
      {:ok,
       attrs
       |> Map.put("encrypted_dek", encrypted_dek)
       |> Map.put("nonce", nonce)
       |> Map.put("authorization_public_key_material", attrs["authorization_public_key_material"])
       |> Map.put("share_keys", share_keys)
       |> Map.put("salt", salt)
       |> Map.put("auth_key", auth_key)}
    else
      {:error, field} ->
        {:error, field}
    end
  end

  defp decode_required_binary_field(value, field) do
    case decode_binary(value) do
      {:ok, decoded} -> {:ok, decoded}
      _ -> {:error, field}
    end
  end

  defp decode_optional_binary_field(nil, _field), do: {:ok, nil}

  defp decode_optional_binary_field(value, field) do
    case decode_binary(value) do
      {:ok, decoded} -> {:ok, decoded}
      _ -> {:error, field}
    end
  end

  defp decode_share_keys(nil), do: {:ok, nil}

  defp decode_share_keys(share_keys) when is_list(share_keys) do
    share_keys
    |> Enum.reduce_while({:ok, []}, fn share_key, {:ok, acc} ->
      case decode_share_key_item(share_key) do
        {:ok, decoded} -> {:cont, {:ok, [decoded | acc]}}
        {:error, field} -> {:halt, {:error, field}}
      end
    end)
    |> case do
      {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
      error -> error
    end
  end

  defp decode_share_keys(_share_keys), do: {:error, "share_keys"}

  defp decode_share_key_item(%{"encrypted_dek" => encrypted_dek} = share_key) do
    with {:ok, decoded_encrypted_dek} <-
           decode_required_binary_field(encrypted_dek, "share_keys.encrypted_dek"),
         {:ok, decoded_nonce} <-
           decode_optional_binary_field(share_key["nonce"], "share_keys.nonce") do
      {:ok,
       share_key
       |> Map.put("encrypted_dek", decoded_encrypted_dek)
       |> Map.put("nonce", decoded_nonce)}
    end
  end

  defp decode_share_key_item(_share_key), do: {:error, "share_keys"}

  defp decode_share_key_update_params(attrs) do
    with {:ok, decoded_add_keys} <-
           decode_optional_share_key_update_list(attrs, "add_keys"),
         {:ok, decoded_replace_keys} <-
           decode_optional_share_key_update_list(attrs, "replace_keys") do
      {:ok,
       attrs
       |> maybe_put_decoded_share_key_update("add_keys", decoded_add_keys)
       |> maybe_put_decoded_share_key_update("replace_keys", decoded_replace_keys)}
    end
  end

  defp decode_optional_share_key_update_list(attrs, field) do
    case Map.fetch(attrs, field) do
      {:ok, value} -> decode_share_key_update_list(value, field)
      :error -> {:ok, :missing}
    end
  end

  defp maybe_put_decoded_share_key_update(attrs, _field, :missing), do: attrs
  defp maybe_put_decoded_share_key_update(attrs, field, values), do: Map.put(attrs, field, values)

  defp decode_share_key_update_list(nil, field), do: {:error, {:invalid_format, field}}

  defp decode_share_key_update_list(values, field) when is_list(values) do
    values
    |> Enum.reduce_while({:ok, []}, fn share_key, {:ok, acc} ->
      case decode_share_key_item(share_key, field) do
        {:ok, decoded} -> {:cont, {:ok, [decoded | acc]}}
        {:error, item_field} -> {:halt, {:error, {:invalid_format, item_field}}}
      end
    end)
    |> case do
      {:ok, decoded} -> {:ok, Enum.reverse(decoded)}
      error -> error
    end
  end

  defp decode_share_key_update_list(_values, field),
    do: {:error, {:invalid_format, field}}

  defp decode_share_key_item(%{"encrypted_dek" => encrypted_dek} = share_key, field) do
    with {:ok, decoded_encrypted_dek} <-
           decode_required_binary_field(encrypted_dek, "#{field}.encrypted_dek"),
         {:ok, decoded_nonce} <-
           decode_optional_binary_field(share_key["nonce"], "#{field}.nonce") do
      {:ok,
       share_key
       |> Map.put("encrypted_dek", decoded_encrypted_dek)
       |> Map.put("nonce", decoded_nonce)}
    end
  end

  defp decode_share_key_item(_share_key, field), do: {:error, field}

  defp handle_create_error(conn, {:invalid_uuid, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_uuid", field: field})
  end

  defp handle_create_error(conn, {:missing_field, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_field", field: field})
  end

  defp handle_create_error(conn, {:invalid_value, field}) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_value", field: field})
  end

  defp handle_create_error(conn, {:invalid_datetime, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_datetime", field: field})
  end

  defp handle_create_error(conn, {:invalid_integer, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_integer", field: field})
  end

  defp handle_create_error(conn, :invalid_token) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_share_slug"})
  end

  defp handle_create_error(conn, :invalid_token_prefix) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_token_prefix"})
  end

  defp handle_create_error(conn, :invalid_encrypted_dek) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_encrypted_dek"})
  end

  defp handle_create_error(conn, :invalid_nonce) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_nonce"})
  end

  defp handle_create_error(conn, :invalid_kdf_params) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_kdf_params"})
  end

  defp handle_create_error(conn, :invalid_auth_key) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_auth_key"})
  end

  defp handle_create_error(conn, :folder_not_supported) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "folder_not_supported"})
  end

  defp handle_create_error(conn, %Ecto.Changeset{} = changeset) do
    if has_unique_constraint_error?(changeset) do
      conn |> put_status(:conflict) |> json(%{error: "share_conflict"})
    else
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "validation_error", details: format_errors(changeset)})
    end
  end

  defp handle_create_error(conn, reason) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: to_string(reason)})
  end

  defp validate_uuid_param(value, field) do
    case Ecto.UUID.cast(value) do
      {:ok, _uuid} -> :ok
      :error -> {:error, {:invalid_uuid, field}}
    end
  end

  defp handle_manage_error(conn, {:invalid_uuid, field}) do
    if field == :share_id do
      handle_manage_error(conn, :not_found)
    else
      conn |> put_status(:bad_request) |> json(%{error: "invalid_uuid", field: field})
    end
  end

  defp handle_manage_error(conn, {:invalid_datetime, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_datetime", field: field})
  end

  defp handle_manage_error(conn, {:invalid_integer, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_integer", field: field})
  end

  defp handle_manage_error(conn, {:invalid_value, field}) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_value", field: field})
  end

  defp handle_manage_error(conn, :invalid_encrypted_dek) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_encrypted_dek"})
  end

  defp handle_manage_error(conn, :invalid_nonce) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_nonce"})
  end

  defp handle_manage_error(conn, :missing_update_fields) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_update_fields"})
  end

  defp handle_manage_error(conn, :not_found) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_manage_error(conn, %Ecto.Changeset{} = changeset) do
    if child_share_unique_constraint_error?(changeset) do
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "invalid_value", field: "add_keys"})
    else
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "validation_error", details: format_errors(changeset)})
    end
  end

  defp handle_manage_error(conn, reason) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: to_string(reason)})
  end

  defp child_share_unique_constraint_error?(%Ecto.Changeset{} = changeset) do
    Enum.any?(changeset.constraints, fn constraint ->
      constraint.constraint == "shares_parent_share_document_id_index"
    end)
  end
end
