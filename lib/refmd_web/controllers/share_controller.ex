defmodule RefMDWeb.ShareController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Documents, Sharing}
  alias RefMD.Encryption.KeyDirectory.PinBootstrap

  alias RefMDWeb.Channels.Document.Bootstrap, as: DocumentBootstrap
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
    case Sharing.get_share_landing(share_slug, get_session_token(conn)) do
      {:ok, %{share: share, root: root}} ->
        conn
        |> no_store()
        |> json(landing_response(share, root))

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
    allowed = [
      "share_slug",
      "display_name",
      "share_participant_device_id",
      "share_participant_principal_id",
      "share_participant_session_id",
      "hybrid_signing_public_key_material",
      "hybrid_encryption_public_key_material",
      "share_capability_authorization",
      "share_participant_device_authorization"
    ]

    with :ok <- reject_extra_fields(params, allowed),
         attrs <-
           params
           |> Map.take([
             "display_name",
             "share_participant_device_id",
             "share_participant_principal_id",
             "share_participant_session_id",
             "hybrid_signing_public_key_material",
             "hybrid_encryption_public_key_material",
             "share_capability_authorization",
             "share_participant_device_authorization"
           ])
           |> decode_share_participant_fields([]),
         {:ok, decoded} <- attrs do
      conn
      |> no_store()
      |> render_bootstrap_result(Sharing.bootstrap_participant(share_slug, decoded))
    else
      {:error, :unexpected_field} ->
        conn |> put_status(:bad_request) |> json(%{error: "unexpected_field"})

      {:error, field} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_format", field: field})
    end
  end

  defp reject_extra_fields(params, allowed) do
    allowed = MapSet.new(allowed)

    if Enum.all?(Map.keys(params), &MapSet.member?(allowed, &1)),
      do: :ok,
      else: {:error, :unexpected_field}
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
    allowed = [
      "share_slug",
      "response",
      "display_name",
      "share_participant_device_id",
      "share_participant_principal_id",
      "share_participant_session_id",
      "hybrid_signing_public_key_material",
      "hybrid_encryption_public_key_material",
      "share_capability_authorization",
      "share_participant_device_authorization",
      "password_challenge_hash"
    ]

    with :ok <- reject_extra_fields(params, allowed),
         attrs <-
           params
           |> Map.take([
             "response",
             "display_name",
             "share_participant_device_id",
             "share_participant_principal_id",
             "share_participant_session_id",
             "hybrid_signing_public_key_material",
             "hybrid_encryption_public_key_material",
             "share_capability_authorization",
             "share_participant_device_authorization",
             "password_challenge_hash"
           ])
           |> decode_share_participant_fields(["response"]),
         {:ok, decoded} <- attrs do
      conn
      |> no_store()
      |> render_bootstrap_result(Sharing.respond_password_challenge(share_slug, decoded))
    else
      {:error, :unexpected_field} ->
        conn |> put_status(:bad_request) |> json(%{error: "unexpected_field"})

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
        {"Document route metadata", "application/json",
         %OpenApiSpex.Schema{
           oneOf: [
             Schemas.ShareDocumentBootstrapRequiredResponse,
             Schemas.ShareDocumentRouteMetadataResponse
           ]
         }},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec document(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def document(conn, %{"document_token" => document_token}) do
    case Sharing.get_document_bootstrap(document_token, get_session_token(conn), nil) do
      {:ok, response} ->
        conn
        |> no_store()
        |> json(response)

      {:error, _reason} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:document_bootstrap,
    summary: "Bootstrap canonical document share content",
    parameters: [
      document_token: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Canonical bootstrap params", "application/json", Schemas.ShareCanonicalBootstrapRequest},
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

  @spec document_bootstrap(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def document_bootstrap(conn, %{"document_token" => document_token} = params) do
    case validate_canonical_pin_hash(params) do
      {:ok, pin_hash} ->
        case Sharing.get_document_bootstrap(
               document_token,
               get_session_token(conn),
               pin_hash
             ) do
          {:ok, response} ->
            conn
            |> no_store()
            |> json(encode_document_bootstrap(response, pin_hash))

          {:error, _reason} ->
            conn |> put_status(:not_found) |> json(%{error: "not_found"})
        end

      {:error, reason} ->
        handle_canonical_bootstrap_error(conn, reason)
    end
  end

  operation(:folder,
    summary: "Get canonical folder route metadata for a share",
    parameters: [
      folder_token: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok:
        {"Folder route metadata", "application/json",
         %OpenApiSpex.Schema{
           oneOf: [
             Schemas.ShareDocumentBootstrapRequiredResponse,
             Schemas.ShareFolderRouteMetadataResponse
           ]
         }},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec folder(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def folder(conn, %{"folder_token" => folder_token}) do
    case Sharing.get_folder_bootstrap(folder_token, get_session_token(conn), nil) do
      {:ok, response} ->
        conn
        |> no_store()
        |> json(response)

      {:error, _reason} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:folder_bootstrap,
    summary: "Bootstrap canonical folder share content",
    parameters: [
      folder_token: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Canonical bootstrap params", "application/json", Schemas.ShareCanonicalBootstrapRequest},
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

  @spec folder_bootstrap(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def folder_bootstrap(conn, %{"folder_token" => folder_token} = params) do
    case validate_canonical_pin_hash(params) do
      {:ok, pin_hash} ->
        case Sharing.get_folder_bootstrap(
               folder_token,
               get_session_token(conn),
               pin_hash
             ) do
          {:ok, response} ->
            conn
            |> no_store()
            |> json(encode_folder_bootstrap(response))

          {:error, _reason} ->
            conn |> put_status(:not_found) |> json(%{error: "not_found"})
        end

      {:error, reason} ->
        handle_canonical_bootstrap_error(conn, reason)
    end
  end

  defp serialize_share(share) do
    %{
      id: share.id,
      document_id: share.document_id,
      scope: share.scope,
      permission: share.permission,
      created_event_hash: share.created_event_hash,
      latest_bootstrap_event_hash: share.latest_bootstrap_event_hash,
      capability_context_hash: share.capability_context_hash,
      share_capability_secret_commitment: share.share_capability_secret_commitment,
      password_capability_secret_commitment: share.password_capability_secret_commitment,
      password_protected: share.password_protected
    }
  end

  defp landing_response(%{password_protected: true} = share, _root) do
    %{share: serialize_share(share), password_challenge_required: true}
  end

  defp landing_response(share, root) do
    %{share: serialize_share(share), root: root}
  end

  defp no_store(conn) do
    put_resp_header(conn, "cache-control", "no-store")
  end

  defp encode_document_bootstrap(
         %{bootstrap_required: true} = response,
         _authenticated_pin_hash
       ),
       do: response

  defp encode_document_bootstrap(response, authenticated_pin_hash) do
    response
    |> maybe_put_initial_document(authenticated_pin_hash)
    |> Map.update!(:encrypted_dek, &encode_binary/1)
    |> Map.update!(:encrypted_title, &encode_binary/1)
    |> Map.update!(:encrypted_title_nonce, &encode_binary/1)
    |> Map.update!(:nonce, &encode_binary/1)
  end

  defp maybe_put_initial_document(
         %{document_id: document_id, share_id: share_id} = response,
         authenticated_pin_hash
       ) do
    params =
      %{"mode" => "complete"}
      |> maybe_put_authenticated_pin_hash(authenticated_pin_hash)

    with document when not is_nil(document) <- Documents.get_document(document_id),
         {:ok, initial_document} <-
           DocumentBootstrap.load_share_initial_data(document, params, share_id) do
      Map.put(response, :initial_document, initial_document)
    else
      _ -> response
    end
  end

  defp maybe_put_initial_document(response, _authenticated_pin_hash), do: response

  defp maybe_put_authenticated_pin_hash(params, authenticated_pin_hash)
       when is_binary(authenticated_pin_hash),
       do: Map.put(params, "authenticated_workspace_pin_bootstrap_hash", authenticated_pin_hash)

  defp maybe_put_authenticated_pin_hash(params, _authenticated_pin_hash), do: params

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

  defp decode_share_participant_fields(attrs, extra_binary_fields) do
    decode_binary_fields(attrs, extra_binary_fields)
  end

  defp decode_binary_fields(attrs, fields) do
    Enum.reduce_while(fields, {:ok, attrs}, fn field, {:ok, acc} ->
      case decode_binary(Map.get(acc, field)) do
        {:ok, decoded} -> {:cont, {:ok, Map.put(acc, field, decoded)}}
        _ -> {:halt, {:error, field}}
      end
    end)
  end

  defp render_bootstrap_result(conn, {:ok, result}) do
    conn
    |> set_share_session_cookie(result.session_token, false)
    |> json(%{
      root: result.root,
      share_id: result.share_id,
      scope_kind: result.scope_kind,
      scope_id: result.scope_id,
      created_event_hash: result.created_event_hash,
      latest_bootstrap_event_hash: result.latest_bootstrap_event_hash,
      capability_context_hash: result.capability_context_hash,
      share_capability_secret_commitment: result.share_capability_secret_commitment,
      password_capability_secret_commitment: result.password_capability_secret_commitment,
      participant: result.participant,
      root_document_bootstrap:
        encode_optional_document_bootstrap(result[:root_document_bootstrap])
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

  defp render_bootstrap_result(conn, {:error, {:invalid_field, field}}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_field", field: field})
  end

  defp render_bootstrap_result(conn, {:error, {:missing_field, field}}) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_field", field: field})
  end

  defp render_bootstrap_result(conn, {:error, :invalid_share_participant_device_authorization}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_share_participant_device_authorization"})
  end

  defp render_bootstrap_result(conn, {:error, :invalid_share_capability_authorization}) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "invalid_share_capability_authorization"})
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

  defp render_bootstrap_result(conn, {:error, reason}) when is_atom(reason) do
    conn |> put_status(:unprocessable_entity) |> json(%{error: Atom.to_string(reason)})
  end

  defp encode_optional_document_bootstrap(nil), do: nil

  defp encode_optional_document_bootstrap(response),
    do: encode_document_bootstrap(response, authenticated_pin_hash(response))

  defp authenticated_pin_hash(%{workspace_id: workspace_id, workspace_pin_bootstrap: bootstrap})
       when is_binary(workspace_id) and is_map(bootstrap) do
    PinBootstrap.hash!(workspace_id, bootstrap)
  rescue
    ArgumentError -> nil
  end

  defp authenticated_pin_hash(_response), do: nil

  defp validate_canonical_pin_hash(%{"authenticated_workspace_pin_bootstrap_hash" => value})
       when is_binary(value) do
    if Regex.match?(~r/^[A-Za-z0-9_-]{43}$/, value) do
      {:ok, value}
    else
      {:error, {:invalid_value, "authenticated_workspace_pin_bootstrap_hash"}}
    end
  end

  defp validate_canonical_pin_hash(_params),
    do: {:error, {:missing_field, "authenticated_workspace_pin_bootstrap_hash"}}

  defp handle_canonical_bootstrap_error(conn, {:missing_field, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "missing_field", field: field})
  end

  defp handle_canonical_bootstrap_error(conn, {:invalid_value, field}) do
    conn |> put_status(:bad_request) |> json(%{error: "invalid_value", field: field})
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
