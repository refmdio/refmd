defmodule RefMDWeb.ShareController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Sharing
  alias RefMDWeb.Schemas

  operation(:show,
    summary: "Get share landing metadata",
    parameters: [
      share_slug: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Share landing", "application/json", Schemas.ShareLandingResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"share_slug" => share_slug}) do
    case Sharing.get_share_landing(share_slug) do
      {:ok, %{share: share, root: root}} ->
        conn
        |> no_store()
        |> json(%{share: serialize_share(share), root: root})

      {:error, :invalid_slug} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:bootstrap,
    summary: "Bootstrap a share participant session",
    parameters: [
      share_slug: [in: :path, type: :string, required: true]
    ],
    request_body: {"Bootstrap params", "application/json", Schemas.ShareBootstrapRequest},
    responses: [
      ok: {"Bootstrap result", "application/json", Schemas.ShareBootstrapResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec bootstrap(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def bootstrap(conn, %{"share_slug" => share_slug} = params) do
    attrs =
      params
      |> Map.take(["display_name", "device_signing_pub_key", "device_encryption_pub_key"])
      |> decode_binary_fields()

    case attrs do
      {:ok, decoded} ->
        conn
        |> no_store()
        |> render_bootstrap_result(Sharing.bootstrap_participant(share_slug, decoded))

      {:error, field} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_format", field: field})
    end
  end

  operation(:challenge,
    summary: "Get a password challenge for a share",
    parameters: [
      share_slug: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Password challenge", "application/json", Schemas.SharePasswordChallengeResponse}
    ]
  )

  @spec challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def challenge(conn, %{"share_slug" => share_slug}) do
    case Sharing.get_password_challenge(share_slug) do
      {:ok, response} ->
        conn
        |> no_store()
        |> json(%{
          challenge: encode_binary(response.challenge),
          salt: encode_binary(response.salt),
          kdf_params: response.kdf_params
        })

      {:error, _reason} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:respond_challenge,
    summary: "Respond to a password challenge for a share",
    parameters: [
      share_slug: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Challenge response", "application/json", Schemas.SharePasswordChallengeRequest},
    responses: [
      ok: {"Bootstrap result", "application/json", Schemas.ShareBootstrapResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec respond_challenge(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def respond_challenge(conn, %{"share_slug" => share_slug} = params) do
    attrs =
      params
      |> Map.take([
        "response",
        "display_name",
        "device_signing_pub_key",
        "device_encryption_pub_key"
      ])
      |> decode_challenge_fields()

    case attrs do
      {:ok, decoded} ->
        conn
        |> no_store()
        |> render_bootstrap_result(Sharing.respond_password_challenge(share_slug, decoded))

      {:error, field} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_format", field: field})
    end
  end

  operation(:document,
    summary: "Get canonical document bootstrap for a share",
    parameters: [
      document_token: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok:
        {"Document bootstrap", "application/json",
         %OpenApiSpex.Schema{
           oneOf: [
             Schemas.ShareDocumentBootstrapResponse,
             Schemas.ShareDocumentBootstrapRequiredResponse
           ]
         }},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec document(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def document(conn, %{"document_token" => document_token}) do
    case Sharing.get_document_bootstrap(document_token, get_session_token(conn)) do
      {:ok, response} ->
        conn
        |> no_store()
        |> json(encode_document_bootstrap(response))

      {:error, _reason} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:folder,
    summary: "Get canonical folder bootstrap for a share",
    parameters: [
      folder_token: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok:
        {"Folder bootstrap", "application/json",
         %OpenApiSpex.Schema{
           oneOf: [
             Schemas.ShareFolderBootstrapResponse,
             Schemas.ShareDocumentBootstrapRequiredResponse
           ]
         }},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec folder(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def folder(conn, %{"folder_token" => folder_token}) do
    case Sharing.get_folder_bootstrap(folder_token, get_session_token(conn)) do
      {:ok, response} ->
        conn
        |> no_store()
        |> json(encode_folder_bootstrap(response))

      {:error, _reason} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  defp serialize_share(share) do
    %{
      id: share.id,
      document_id: share.document_id,
      scope: share.scope,
      permission: share.permission,
      password_protected: share.password_protected
    }
  end

  defp no_store(conn) do
    put_resp_header(conn, "cache-control", "no-store")
  end

  defp encode_document_bootstrap(%{bootstrap_required: true} = response), do: response

  defp encode_document_bootstrap(response) do
    response
    |> Map.update!(:encrypted_dek, &encode_binary/1)
    |> Map.update!(:encrypted_title, &encode_binary/1)
    |> Map.update!(:encrypted_title_nonce, &encode_binary/1)
    |> Map.update!(:nonce, &encode_binary/1)
  end

  defp encode_folder_bootstrap(%{bootstrap_required: true} = response), do: response

  defp encode_folder_bootstrap(response) do
    response
    |> Map.update!(:folder, &encode_share_tree_entry/1)
    |> Map.update!(:entries, fn entries -> Enum.map(entries, &encode_share_tree_entry/1) end)
  end

  defp encode_share_tree_entry(entry) do
    entry
    |> Map.update!(:encrypted_dek, &encode_binary/1)
    |> Map.update!(:encrypted_title, &encode_binary/1)
    |> Map.update!(:encrypted_title_nonce, &encode_binary/1)
    |> Map.update!(:nonce, &encode_binary/1)
  end

  defp decode_binary_fields(attrs) do
    with {:ok, signing_key} <- decode_binary(attrs["device_signing_pub_key"]),
         {:ok, encryption_key} <- decode_binary(attrs["device_encryption_pub_key"]) do
      {:ok,
       attrs
       |> Map.put("device_signing_pub_key", signing_key)
       |> Map.put("device_encryption_pub_key", encryption_key)}
    else
      _ ->
        if attrs["device_signing_pub_key"] == nil,
          do: {:error, "device_signing_pub_key"},
          else: {:error, "device_encryption_pub_key"}
    end
  end

  defp decode_challenge_fields(attrs) do
    with {:ok, response} <- decode_binary(attrs["response"]),
         {:ok, signing_key} <- decode_binary(attrs["device_signing_pub_key"]),
         {:ok, encryption_key} <- decode_binary(attrs["device_encryption_pub_key"]) do
      {:ok,
       attrs
       |> Map.put("response", response)
       |> Map.put("device_signing_pub_key", signing_key)
       |> Map.put("device_encryption_pub_key", encryption_key)}
    else
      _ ->
        cond do
          attrs["response"] == nil -> {:error, "response"}
          attrs["device_signing_pub_key"] == nil -> {:error, "device_signing_pub_key"}
          true -> {:error, "device_encryption_pub_key"}
        end
    end
  end

  defp render_bootstrap_result(conn, {:ok, result}) do
    conn
    |> set_share_session_cookie(result.session_token, false)
    |> json(%{
      root: result.root,
      participant: result.participant
    })
  end

  defp render_bootstrap_result(conn, {:error, :password_required}) do
    conn |> put_status(:conflict) |> json(%{error: "password_required"})
  end

  defp render_bootstrap_result(conn, {:error, :invalid_response}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_response"})
  end

  defp render_bootstrap_result(conn, {:error, :invalid_display_name}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_display_name"})
  end

  defp render_bootstrap_result(conn, {:error, {:invalid_key_size, field}}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_key_size", field: field})
  end

  defp render_bootstrap_result(conn, {:error, {:invalid_public_key, field}}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_public_key", field: field})
  end

  defp render_bootstrap_result(conn, {:error, :invalid_token}) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp render_bootstrap_result(conn, {:error, :not_found}) do
    conn |> put_status(:not_found) |> json(%{error: "not_found"})
  end

  defp render_bootstrap_result(conn, {:error, %Ecto.Changeset{} = changeset}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "validation_error", details: format_errors(changeset)})
  end

  defp get_session_token(conn) do
    conn
    |> get_req_header("cookie")
    |> List.first("")
    |> String.split(";")
    |> Enum.find_value(fn part ->
      case String.trim(part) |> String.split("=", parts: 2) do
        ["_refmd_share_session", value] -> value
        _ -> nil
      end
    end)
  end
end
