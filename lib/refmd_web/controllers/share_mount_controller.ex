defmodule RefMDWeb.ShareMountController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Auth.DBSC, as: AuthDBSC
  alias RefMD.Crypto.Encoding
  alias RefMD.Sharing

  alias RefMDWeb.Http.DBSC, as: HttpDBSC
  alias RefMDWeb.Schemas

  operation(:share_mounts_for_share,
    summary: "List current user's saved mounts for a share link",
    parameters: [
      share_slug: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Share link mount list", "application/json", Schemas.ShareLinkMountListResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def share_mounts_for_share(conn, %{"share_slug" => share_slug}) do
    case Sharing.list_share_mounts_for_share(conn.assigns.current_user_id, share_slug) do
      {:ok, response} ->
        json(conn, response)

      {:error, reason} ->
        handle_error(conn, reason)
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

  def create(conn, params) do
    attrs =
      Map.take(params, [
        "workspace_id",
        "share_slug",
        "target_kind",
        "target_token",
        "parent_id",
        "authenticated_workspace_pin_bootstrap_hash"
      ])
      |> Map.put("__share_session_token", get_share_session_token(conn))

    case Sharing.create_share_mount(conn.assigns.current_user_id, attrs) do
      {:ok, response} ->
        conn |> put_status(:created) |> json(encode_mount_placement(response))

      {:error, {:conflict, payload}} ->
        conn |> put_status(:conflict) |> json(%{mount: encode_mount_placement(payload.mount)})

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

  def index(conn, %{"workspace_id" => workspace_id}) do
    case validate_uuid_param(workspace_id, :workspace_id) do
      :ok ->
        case Sharing.list_share_mounts(conn.assigns.current_user_id, workspace_id) do
          {:ok, response} ->
            json(conn, %{mounts: Enum.map(response.mounts, &encode_mount_list_item/1)})

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
      mount_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Share mount", "application/json", Schemas.ShareMountMetadataResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show(conn, %{"mount_id" => mount_id}) do
    case validate_uuid_param(mount_id, :mount_id) do
      :ok ->
        case Sharing.get_share_mount(conn.assigns.current_user_id, mount_id) do
          {:ok, response} ->
            json(conn, encode_mount_metadata(response))

          {:error, reason} ->
            handle_error(conn, reason)
        end

      {:error, reason} ->
        handle_error(conn, reason)
    end
  end

  operation(:document_bootstrap,
    summary: "Bootstrap a mounted document",
    parameters: [
      mount_id: [in: :path, type: :string, required: true],
      document_token: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Mount bootstrap params", "application/json", Schemas.ShareMountBootstrapRequest},
    responses: [
      ok: {"Share mount document", "application/json", Schemas.ShareMountDocumentResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def document_bootstrap(
        conn,
        %{"mount_id" => mount_id, "document_token" => document_token} = params
      ) do
    with :ok <- validate_uuid_param(mount_id, :mount_id),
         {:ok, mount_password_session} <- get_mount_password_session(conn, mount_id),
         {:ok, mount_trust_anchor} <- validate_mount_trust_anchor(params) do
      case Sharing.get_share_mount_document_by_token(
             conn.assigns.current_user_id,
             mount_id,
             document_token,
             conn.assigns.rrp_device_id,
             mount_trust_anchor,
             get_share_session_token(conn),
             mount_password_session
           ) do
        {:ok, response} ->
          conn
          |> maybe_set_mount_share_session_cookie(response)
          |> json(encode_mount_document_response(response))

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
      ok: {"Challenge result", "application/json", Schemas.ShareMountChallengeResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def respond_challenge(conn, %{"mount_id" => mount_id, "response" => response} = params) do
    with :ok <- validate_uuid_param(mount_id, :mount_id),
         {:ok, challenge_hash} <-
           validate_password_challenge_hash(params["password_challenge_hash"]),
         {:ok, decoded} <- decode_mount_binary(response) do
      case Sharing.respond_share_mount_challenge(
             conn.assigns.current_user_id,
             mount_id,
             conn.assigns.rrp_device_id,
             decoded,
             nil,
             challenge_hash,
             get_share_session_token(conn)
           ) do
        {:ok, payload} ->
          conn
          |> maybe_set_mount_share_session_cookie(payload)
          |> maybe_set_mount_password_session_cookie(payload)
          |> json(encode_mount_challenge_response(payload))

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

  defp maybe_set_mount_share_session_cookie(conn, %{
         session_token: token,
         share_participant_session: session
       })
       when is_binary(token) and is_map(session) do
    conn
    |> set_share_session_cookie(token, false)
    |> put_registration_header(:share_participant, session)
  end

  defp maybe_set_mount_share_session_cookie(conn, %{session_token: token})
       when is_binary(token) do
    set_share_session_cookie(conn, token, false)
  end

  defp maybe_set_mount_share_session_cookie(conn, _payload), do: conn

  operation(:folder_bootstrap,
    summary: "Bootstrap a mounted folder subtree",
    parameters: [
      mount_id: [in: :path, type: :string, required: true],
      folder_token: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Mount bootstrap params", "application/json", Schemas.ShareMountBootstrapRequest},
    responses: [
      ok: {"Mounted folder subtree", "application/json", Schemas.ShareMountFolderResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      unauthorized: {"Unauthorized", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def folder_bootstrap(conn, %{"mount_id" => mount_id, "folder_token" => folder_token} = params) do
    with :ok <- validate_uuid_param(mount_id, :mount_id),
         {:ok, mount_password_session} <- get_mount_password_session(conn, mount_id),
         {:ok, mount_trust_anchor} <- validate_mount_trust_anchor(params) do
      case Sharing.get_share_mount_folder(
             conn.assigns.current_user_id,
             mount_id,
             folder_token,
             conn.assigns.rrp_device_id,
             mount_trust_anchor,
             get_share_session_token(conn),
             mount_password_session
           ) do
        {:ok, response} ->
          conn
          |> maybe_set_mount_share_session_cookie(response)
          |> json(encode_mount_folder_response(response))

        {:error, reason} ->
          handle_error(conn, reason)
      end
    else
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

  def update(conn, %{"mount_id" => mount_id} = params) do
    case validate_uuid_param(mount_id, :mount_id) do
      :ok ->
        attrs = Map.take(params, ["parent_id", "position"])

        case Sharing.update_share_mount(conn.assigns.current_user_id, mount_id, attrs) do
          {:ok, response} ->
            json(conn, encode_mount_placement(response))

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

  defp encode_mount_summary(mount) do
    mount
  end

  defp encode_mount_placement(mount) do
    encode_mount_summary(mount)
  end

  defp encode_mount_list_item(mount) do
    mount
    |> encode_mount_summary()
    |> Map.delete(:workspace_id)
  end

  defp encode_mount_folder_response(response) do
    %{
      mount: response.mount,
      folder: encode_mount_tree_entry(response.folder),
      entries: Enum.map(response.entries, &encode_mount_tree_entry/1)
    }
  end

  defp encode_mount_challenge_response(%{
         mount_id: mount_id,
         bootstrap_required: bootstrap_required
       }) do
    %{mount_id: mount_id, bootstrap_required: bootstrap_required}
  end

  defp maybe_set_mount_password_session_cookie(conn, %{mount_password_session: session})
       when is_map(session) do
    token =
      Phoenix.Token.sign(
        RefMDWeb.Endpoint,
        "mount_password_session",
        %{
          "mount_id" => session.mount_id,
          "share_id" => session.share_id,
          "user_id" => session.user_id
        }
      )

    conn
    |> set_mount_session_cookie(token, false)
    |> put_registration_header(:mount, %{id: session.mount_id})
  end

  defp maybe_set_mount_password_session_cookie(conn, _payload), do: conn

  defp encode_mount_document_response(%{mount: _mount, document: _document} = response) do
    response
    |> Map.drop([:session_token, :share_participant_session])
    |> Map.update!(:mount, &encode_mount_bootstrap_summary/1)
    |> Map.update!(:document, fn document ->
      document
      |> encode_mount_document()
      |> Map.drop([:title])
    end)
  end

  defp encode_mount_bootstrap_summary(mount) do
    Map.take(mount, [:id, :share_id, :status])
  end

  defp encode_mount_metadata(%{mount: mount, bootstrap_required: bootstrap_required}) do
    %{
      mount: encode_mount_placement(mount),
      bootstrap_required: bootstrap_required
    }
  end

  defp encode_mount_document(document) do
    document
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

  defp encode_mount_tree_entry(entry) do
    entry
    |> encode_share_tree_entry()
    |> Map.drop([:title])
  end

  defp encode_mount_binary(nil), do: nil
  defp encode_mount_binary(value), do: Base.url_encode64(value, padding: false)

  defp decode_mount_binary(value) when is_binary(value) do
    {:ok, Encoding.decode_base64url!(value)}
  rescue
    ArgumentError -> {:error, :invalid_binary}
  end

  defp validate_uuid_param(value, field) do
    case Ecto.UUID.cast(value) do
      {:ok, _uuid} -> :ok
      :error -> {:error, {:invalid_uuid, field}}
    end
  end

  defp validate_mount_pin_hash(value) when is_binary(value) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, value),
      do: {:ok, value},
      else: {:error, {:invalid_value, :authenticated_workspace_pin_bootstrap_hash}}
  end

  defp validate_mount_pin_hash(_),
    do: {:error, {:missing_field, :authenticated_workspace_pin_bootstrap_hash}}

  defp validate_mount_trust_anchor(params) do
    with {:ok, pin_hash} <-
           validate_mount_pin_hash(params["authenticated_workspace_pin_bootstrap_hash"]) do
      {:ok,
       %{
         authenticated_workspace_pin_bootstrap_hash: pin_hash
       }}
    end
  end

  defp validate_password_challenge_hash(value) when is_binary(value) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, value),
      do: {:ok, value},
      else: {:error, {:invalid_value, :password_challenge_hash}}
  end

  defp validate_password_challenge_hash(_),
    do: {:error, {:missing_field, :password_challenge_hash}}

  defp get_share_session_token(conn) do
    conn
    |> get_req_header("cookie")
    |> List.first("")
    |> String.split(";")
    |> Enum.find_value(fn part ->
      case String.trim(part) |> String.split("=", parts: 2) do
        ["__Host-refmd-share-session", value] -> value
        _ -> nil
      end
    end)
  end

  defp get_mount_password_session(conn, mount_id) do
    cookie = mount_session_cookie(conn)

    with :ok <- require_mount_dbsc_bound_cookie(mount_id, cookie) do
      {:ok, verify_mount_password_session_token(cookie, mount_id)}
    end
  end

  defp mount_session_cookie(conn) do
    conn
    |> get_req_header("cookie")
    |> List.first("")
    |> String.split(";")
    |> Enum.find_value(fn part ->
      case String.trim(part) |> String.split("=", parts: 2) do
        ["__Host-refmd-mount-session", value] -> value
        _ -> nil
      end
    end)
  end

  defp require_mount_dbsc_bound_cookie(mount_id, cookie) do
    case AuthDBSC.bound_cookie_status("mount", mount_id, cookie) do
      :not_registered -> :ok
      {:ok, _binding} -> :ok
      {:error, binding} -> {:error, {:dbsc_required, binding}}
    end
  end

  defp verify_mount_password_session_token(nil, _mount_id), do: nil

  defp verify_mount_password_session_token(token, mount_id) do
    with {:ok, signed_token} <- Base.url_decode64(token, padding: false),
         {:ok, %{"mount_id" => ^mount_id, "share_id" => share_id, "user_id" => user_id}} <-
           Phoenix.Token.verify(RefMDWeb.Endpoint, "mount_password_session", signed_token,
             max_age: 24 * 60 * 60
           ),
         true <- is_binary(share_id) and is_binary(user_id) do
      %{mount_id: mount_id, share_id: share_id, user_id: user_id}
    else
      _ -> nil
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

  defp handle_error(conn, :fresh_share_participant_device_required) do
    conn
    |> put_status(:conflict)
    |> json(%{error: "fresh_share_participant_device_required"})
  end

  defp handle_error(conn, {:dbsc_required, binding}) do
    conn
    |> HttpDBSC.put_challenge_header(binding)
    |> put_status(:unauthorized)
    |> json(%{error: "dbsc_required"})
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
