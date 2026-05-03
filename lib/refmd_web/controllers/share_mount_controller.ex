defmodule RefMDWeb.ShareMountController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Sharing
  alias RefMDWeb.Schemas

  operation(:share_mounts,
    summary: "List saved mounts for a share",
    parameters: [
      share_slug: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Share mounts", "application/json", Schemas.ShareMountLookupResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec share_mounts(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def share_mounts(conn, %{"share_slug" => share_slug}) do
    case Sharing.list_share_mounts_for_share(conn.assigns.current_user_id, share_slug) do
      {:ok, response} ->
        json(conn, response)

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:create,
    summary: "Create a share mount",
    request_body: {"Share mount params", "application/json", Schemas.CreateShareMountRequest},
    responses: [
      created: {"Created mount", "application/json", Schemas.ShareMountCreateResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ShareMountConflictResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    attrs =
      Map.take(params, ["workspace_id", "share_slug", "target_kind", "target_token", "parent_id"])

    case Sharing.create_share_mount(conn.assigns.current_user_id, attrs) do
      {:ok, response} ->
        conn |> put_status(:created) |> json(encode_mount_summary(response))

      {:error, {:conflict, payload}} ->
        conn |> put_status(:conflict) |> json(%{mount: encode_mount_summary(payload.mount)})

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:index,
    summary: "List share mounts for a workspace",
    parameters: [
      workspace_id: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Share mount list", "application/json", Schemas.ShareMountListResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, %{"workspace_id" => workspace_id}) do
    case validate_uuid_param(workspace_id, :workspace_id) do
      :ok ->
        case Sharing.list_share_mounts(conn.assigns.current_user_id, workspace_id) do
          {:ok, response} ->
            json(conn, %{mounts: Enum.map(response.mounts, &encode_mount_summary/1)})

          {:error, reason} ->
            handle_error(conn, reason)
        end

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:show,
    summary: "Get a share mount",
    parameters: [
      mount_id: [in: :path, type: :string, required: true],
      share: [in: :query, type: :string, required: false],
      document_id: [in: :query, type: :string, required: false]
    ],
    responses: [
      ok: {"Share mount", "application/json", Schemas.ShareMountDetailResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"mount_id" => mount_id} = params) do
    with :ok <- validate_uuid_param(mount_id, :mount_id),
         {:ok, share_id} <- validate_optional_uuid_param(params["share"], :share),
         {:ok, document_id} <- validate_optional_uuid_param(params["document_id"], :document_id) do
      result =
        cond do
          is_binary(share_id) ->
            Sharing.get_share_mount_share(conn.assigns.current_user_id, mount_id, share_id)

          is_nil(document_id) ->
            Sharing.get_share_mount(conn.assigns.current_user_id, mount_id)

          true ->
            Sharing.get_share_mount_document(conn.assigns.current_user_id, mount_id, document_id)
        end

      case result do
        {:ok, response} ->
          json(conn, encode_mount_detail(response))

        {:error, reason} ->
          handle_error(conn, reason)
      end
    else
      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:challenge,
    summary: "Get a password challenge for a mounted share",
    parameters: [
      mount_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Password challenge", "application/json", Schemas.SharePasswordChallengeResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def challenge(conn, %{"mount_id" => mount_id}) do
    case validate_uuid_param(mount_id, :mount_id) do
      :ok ->
        case Sharing.get_share_mount_challenge(conn.assigns.current_user_id, mount_id) do
          {:ok, response} ->
            conn
            |> put_resp_header("cache-control", "no-store")
            |> json(%{
              challenge: encode_mount_binary(response.challenge),
              salt: encode_mount_binary(response.salt),
              kdf_params: response.kdf_params
            })

          {:error, reason} ->
            handle_error(conn, reason)
        end

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:respond_challenge,
    summary: "Respond to a password challenge for a mounted share",
    parameters: [
      mount_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Challenge response", "application/json", Schemas.ShareMountChallengeRequest},
    responses: [
      ok:
        {"Challenge result", "application/json",
         %OpenApiSpex.Schema{
           oneOf: [
             Schemas.ShareMountDocumentChallengeResponse,
             Schemas.ShareMountFolderChallengeResponse
           ]
         }},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec respond_challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def respond_challenge(conn, %{"mount_id" => mount_id, "response" => response} = params) do
    with :ok <- validate_uuid_param(mount_id, :mount_id),
         {:ok, share_id} <- validate_optional_uuid_param(params["share_id"], :share_id),
         {:ok, document_id} <- validate_optional_uuid_param(params["document_id"], :document_id),
         {:ok, decoded} <- decode_mount_binary(response) do
      case Sharing.respond_share_mount_challenge(
             conn.assigns.current_user_id,
             mount_id,
             decoded,
             share_id || document_id
           ) do
        {:ok, payload} ->
          json(conn, encode_mount_detail(payload))

        {:error, reason} ->
          handle_error(conn, reason)
      end
    else
      {:error, :invalid_binary} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_format", field: "response"})

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:folder,
    summary: "Get a mounted folder subtree",
    parameters: [
      mount_id: [in: :path, type: :string, required: true],
      folder_token: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Mounted folder subtree", "application/json", Schemas.ShareMountFolderResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec folder(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def folder(conn, %{"mount_id" => mount_id, "folder_token" => folder_token}) do
    case validate_uuid_param(mount_id, :mount_id) do
      :ok ->
        case Sharing.get_share_mount_folder(conn.assigns.current_user_id, mount_id, folder_token) do
          {:ok, response} ->
            json(conn, encode_mount_folder_response(response))

          {:error, reason} ->
            handle_error(conn, reason)
        end

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:update,
    summary: "Update a share mount position",
    parameters: [
      mount_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Share mount update params", "application/json", Schemas.UpdateShareMountRequest},
    responses: [
      ok: {"Updated mount", "application/json", Schemas.ShareMountResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update(conn, %{"mount_id" => mount_id} = params) do
    case validate_uuid_param(mount_id, :mount_id) do
      :ok ->
        attrs = Map.take(params, ["parent_id", "position"])

        case Sharing.update_share_mount(conn.assigns.current_user_id, mount_id, attrs) do
          {:ok, response} ->
            json(conn, encode_mount_summary(response))

          {:error, reason} ->
            handle_error(conn, reason)
        end

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:delete,
    summary: "Delete a share mount",
    parameters: [
      mount_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      no_content: {"Deleted", "application/json", nil},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"mount_id" => mount_id}) do
    case validate_uuid_param(mount_id, :mount_id) do
      :ok ->
        case Sharing.delete_share_mount(conn.assigns.current_user_id, mount_id) do
          :ok ->
            send_resp(conn, :no_content, "")

          {:error, reason} ->
            handle_error(conn, reason)
        end

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  defp encode_mount_folder_response(response) do
    %{
      mount: response.mount,
      folder: encode_share_tree_entry(response.folder),
      entries: Enum.map(response.entries, &encode_share_tree_entry/1)
    }
  end

  defp encode_mount_detail(%{mount: _mount, admission: admission} = response)
       when is_map(admission) do
    response
    |> Map.update!(:mount, &encode_mount_summary/1)
    |> Map.update!(:admission, &encode_mount_admission/1)
  end

  defp encode_mount_detail(%{admission: admission} = response) when is_map(admission) do
    Map.update!(response, :admission, &encode_mount_admission/1)
  end

  defp encode_mount_detail(%{folder_tree: folder_tree} = response) when is_map(folder_tree) do
    response
    |> Map.update!(:mount, &encode_mount_summary/1)
    |> Map.put(:folder_tree, %{
      folder: encode_share_tree_entry(folder_tree.folder),
      entries: Enum.map(folder_tree.entries, &encode_share_tree_entry/1)
    })
  end

  defp encode_mount_detail(%{mount: _mount} = response) do
    Map.update!(response, :mount, &encode_mount_summary/1)
  end

  defp encode_mount_summary(mount) do
    Map.update!(mount, :target, fn target ->
      target
      |> Map.update!(:encrypted_title, &encode_mount_binary/1)
      |> Map.update!(:encrypted_title_nonce, &encode_mount_binary/1)
    end)
  end

  defp encode_mount_admission(admission) do
    admission
    |> Map.update!(:encrypted_dek, &encode_mount_binary/1)
    |> Map.update!(:encrypted_title, &encode_mount_binary/1)
    |> Map.update!(:encrypted_title_nonce, &encode_mount_binary/1)
    |> Map.update!(:nonce, &encode_mount_binary/1)
  end

  defp encode_share_tree_entry(entry) do
    entry
    |> Map.update!(:encrypted_dek, &encode_mount_binary/1)
    |> Map.update!(:encrypted_title, &encode_mount_binary/1)
    |> Map.update!(:encrypted_title_nonce, &encode_mount_binary/1)
    |> Map.update!(:nonce, &encode_mount_binary/1)
  end

  defp encode_mount_binary(nil), do: nil
  defp encode_mount_binary(value), do: Base.url_encode64(value, padding: false)

  defp decode_mount_binary(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_binary}
    end
  end

  defp validate_uuid_param(value, field) do
    case Ecto.UUID.cast(value) do
      {:ok, _uuid} -> :ok
      :error -> {:error, {:invalid_uuid, field}}
    end
  end

  defp validate_optional_uuid_param(nil, _field), do: {:ok, nil}
  defp validate_optional_uuid_param("", _field), do: {:ok, nil}

  defp validate_optional_uuid_param(value, field) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_uuid, field}}
    end
  end

  defp handle_error(conn, {:invalid_uuid, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_uuid", field: field})
  end

  defp handle_error(conn, {:missing_field, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_field", field: field})
  end

  defp handle_error(conn, {:invalid_value, field}) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_value", field: field})
  end

  defp handle_error(conn, :forbidden) do
    conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
  end

  defp handle_error(conn, :not_found) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp handle_error(conn, %Ecto.Changeset{} = changeset) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "validation_error", details: format_errors(changeset)})
  end

  defp handle_error(conn, reason) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
  end
end
