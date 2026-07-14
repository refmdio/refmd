defmodule RefMDWeb.DocumentKeyController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Documents.DekRotation
  alias RefMD.{Encryption, Sharing, Workspaces}
  alias RefMDWeb.Schemas

  plug RefMDWeb.Plugs.ResolveDocumentWorkspace

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:read"]
       when action in [
              :get_document_keys,
              :get_document_wipe_requirement,
              :acknowledge_document_wipe
            ]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:write"] when action in [:get_rotation_targets]

  plug RefMDWeb.Plugs.RequireRBAC,
       [permission: "document:write"]
       when action in [
              :create_document_key,
              :rewrap_document_key_for_kek_rotation,
              :prepare_dek_rotation_completion,
              :complete_dek_rotation
            ]

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

  def get_document_keys(conn, _params) do
    document = conn.assigns.document

    case require_no_workspace_wipe_requirement(conn, document.workspace_id) do
      :ok ->
        keys = Encryption.list_document_encrypted_keys(document.id)

        json(conn, %{
          keys: Enum.map(keys, &format_document_key/1)
        })

      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:get_rotation_targets,
    summary: "Get share-key targets required before DEK rotation",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Rotation targets", "application/json", Schemas.DocumentKeyRotationTargetsResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_rotation_targets(conn, _params) do
    document = conn.assigns.document

    json(conn, %{
      current_key_version: document.min_dek_version,
      targets: Sharing.list_key_rotation_targets(document, conn.assigns.current_user_id)
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

  def create_document_key(conn, params) do
    document = conn.assigns.document

    attrs = decode_document_key_attrs!(document.id, params)
    share_rotation = decode_share_rotation!(params)

    case require_no_workspace_wipe_requirement(conn, document.workspace_id) do
      :ok ->
        handle_create_document_key_result(
          conn,
          Encryption.create_document_key_with_rotation(attrs, share_rotation)
        )

      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:rewrap_document_key_for_kek_rotation,
    summary: "Rewrap an existing DEK during workspace KEK rotation",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Rewrap params", "application/json", Schemas.RewrapDocumentKeyForKekRotationRequest},
    responses: [
      ok: {"Key rewrapped", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Rewrap rejected", "application/json", Schemas.ErrorResponse}
    ]
  )

  def rewrap_document_key_for_kek_rotation(conn, params) do
    document = conn.assigns.document
    attrs = decode_document_key_attrs!(document.id, params)

    case Encryption.rewrap_document_key_for_kek_rotation(
           document.id,
           params["key_version"],
           params["new_kek_version"],
           attrs
         ) do
      {:ok, _key} ->
        json(conn, %{ok: true})

      {:error, _reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "kek_rotation_rewrap_not_allowed"})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:prepare_dek_rotation_completion,
    summary: "Prepare DEK rotation completion manifest hashes",
    parameters: [
      document_id: [in: :path, type: :string, required: true],
      new_key_version: [in: :query, type: :integer, required: true]
    ],
    responses: [
      ok:
        {"Completion manifest hashes", "application/json",
         Schemas.DekRotationCompletionManifestResponse},
      unprocessable_entity: {"Preconditions not met", "application/json", Schemas.ErrorResponse}
    ]
  )

  def prepare_dek_rotation_completion(conn, %{"new_key_version" => new_key_version}) do
    document = conn.assigns.document

    case parse_positive_integer(new_key_version) do
      {:ok, parsed_key_version} ->
        case DekRotation.completion_materials(document.id, parsed_key_version) do
          {:ok, materials} -> json(conn, materials)
          {:error, reason} -> rotation_error(conn, reason)
        end

      :error ->
        rotation_error(conn, :rotation_snapshot_required)
    end
  end

  operation(:complete_dek_rotation,
    summary: "Complete DEK rotation after snapshot and device deletion coverage",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    request_body: {"Completion params", "application/json", Schemas.DekRotationCompletionRequest},
    responses: [
      ok: {"Rotation completed", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Preconditions not met", "application/json", Schemas.ErrorResponse}
    ]
  )

  def complete_dek_rotation(conn, params) do
    document = conn.assigns.document

    case DekRotation.complete(
           document.id,
           params["new_key_version"],
           params["workspace_key_directory_events"],
           params["workspace_key_directory_checkpoint"],
           params["device_key_deletion_proofs"],
           params["wipe_required_device_ids"]
         ) do
      :ok -> json(conn, %{ok: true})
      {:error, reason} -> rotation_error(conn, reason)
    end
  end

  operation(:get_document_wipe_requirement,
    summary: "Get the current device DEK wipe requirement",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Wipe requirement", "application/json", Schemas.DocumentWipeRequirementResponse},
      not_found: {"No requirement", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_document_wipe_requirement(conn, _params) do
    document = conn.assigns.document

    case DekRotation.wipe_requirement(document.id, conn.assigns.rrp_device_id) do
      {:ok, requirement} ->
        json(conn, requirement)

      {:error, :wipe_requirement_not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "wipe_requirement_not_found"})
    end
  end

  operation(:acknowledge_document_wipe,
    summary: "Acknowledge secure deletion for a DEK wipe requirement",
    parameters: [document_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Deletion proof", "application/json", Schemas.DocumentWipeAcknowledgementRequest},
    responses: [
      ok: {"Acknowledged", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Invalid proof", "application/json", Schemas.ErrorResponse}
    ]
  )

  def acknowledge_document_wipe(conn, params) do
    document = conn.assigns.document

    case DekRotation.acknowledge_wipe(
           document.id,
           conn.assigns.rrp_device_id,
           params["device_key_deletion_proof"]
         ) do
      :ok -> json(conn, %{ok: true})
      {:error, reason} -> rotation_error(conn, reason)
    end
  end

  defp rotation_error(conn, reason) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: Atom.to_string(reason)})
  end

  defp parse_positive_integer(value) when is_integer(value) and value > 0, do: {:ok, value}

  defp parse_positive_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {parsed, ""} when parsed > 0 -> {:ok, parsed}
      _ -> :error
    end
  end

  defp parse_positive_integer(_value), do: :error

  defp decode_document_key_attrs!(document_id, params) do
    %{
      document_id: document_id,
      key_version: params["key_version"],
      kek_version: params["kek_version"],
      encrypted_dek: decode_binary!(params["encrypted_dek"]),
      nonce: decode_binary!(params["nonce"])
    }
  end

  defp decode_share_rotation!(params) do
    %{
      dek_rotation_start_events: params["dek_rotation_start_events"],
      dek_rotation_start_checkpoint: params["dek_rotation_start_checkpoint"],
      share_key_replacements:
        Enum.map(params["share_key_replacements"] || [], &decode_share_key_replacement!/1),
      workspace_key_directory_events: params["workspace_key_directory_events"],
      workspace_key_directory_checkpoint: params["workspace_key_directory_checkpoint"]
    }
  end

  defp decode_share_key_replacement!(replacement) do
    %{
      root_share_id: replacement["root_share_id"],
      share_id: replacement["share_id"],
      document_id: replacement["document_id"],
      key_version: replacement["key_version"],
      encrypted_dek: decode_binary!(replacement["encrypted_dek"]),
      nonce: decode_binary!(replacement["nonce"])
    }
  end

  defp handle_create_document_key_result(conn, {:ok, _key}) do
    conn |> put_status(:created) |> json(%{ok: true})
  end

  defp handle_create_document_key_result(conn, {:error, :kek_version_mismatch}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "kek_version_mismatch"})
  end

  defp handle_create_document_key_result(conn, {:error, :kek_rotation_required}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "kek_rotation_required"})
  end

  defp handle_create_document_key_result(conn, {:error, :dek_rotation_required}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "dek_rotation_required"})
  end

  defp handle_create_document_key_result(conn, {:error, :key_version_too_old}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "key_version_too_old"})
  end

  defp handle_create_document_key_result(conn, {:error, :key_version_not_consecutive}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "key_version_not_consecutive"})
  end

  defp handle_create_document_key_result(conn, {:error, :folders_cannot_have_dek}) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "folders_cannot_have_dek"})
  end

  defp handle_create_document_key_result(conn, {:error, :document_not_found}) do
    conn
    |> put_status(:not_found)
    |> json(%{error: "document_not_found"})
  end

  defp handle_create_document_key_result(conn, {:error, reason})
       when reason in [
              :invalid_share_key_rotation,
              :incomplete_share_key_rotation,
              :invalid_key_directory
            ] do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: Atom.to_string(reason)})
  end

  defp handle_create_document_key_result(conn, {:error, %Ecto.Changeset{} = changeset}) do
    if has_unique_constraint_error?(changeset) do
      conn |> put_status(:conflict) |> json(%{error: "key_version_already_exists"})
    else
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "invalid_key", details: format_errors(changeset)})
    end
  end

  defp require_no_workspace_wipe_requirement(conn, workspace_id) do
    device_id = conn.assigns[:rrp_device_id]
    document_id = conn.assigns.document.id

    if is_binary(device_id) and
         (Workspaces.workspace_device_wipe_required?(workspace_id, device_id) or
            DekRotation.wipe_required?(document_id, device_id)),
       do: {:error, :forbidden, "device_wipe_required"},
       else: :ok
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
