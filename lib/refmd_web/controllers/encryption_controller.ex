defmodule RefMDWeb.EncryptionController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Accounts, Encryption, Workspaces}
  alias RefMDWeb.Schemas

  operation(:create_workspace_key,
    summary: "Create a workspace encryption key",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Key params", "application/json", Schemas.CreateWorkspaceKeyRequest},
    responses: [
      created: {"Key created", "application/json", Schemas.OkResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_workspace_key(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id

    case Encryption.create_workspace_encrypted_key(%{
           workspace_id: workspace_id,
           user_id: user_id,
           device_id: params["device_id"],
           key_version: params["key_version"],
           sender_device_id: params["sender_device_id"],
           encrypted_kek: decode_binary!(params["encrypted_kek"]),
           nonce: decode_binary!(params["nonce"]),
           is_active: params["is_active"] || true
         }) do
      {:ok, _key} ->
        conn |> put_status(:created) |> json(%{ok: true})

      {:error, :invalid_sender_device} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_sender_device"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_key", details: format_errors(changeset)})
    end
  end

  operation(:get_workspace_keys,
    summary: "Get workspace encryption keys",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Workspace keys", "application/json", Schemas.WorkspaceKeysResponse}
    ]
  )

  def get_workspace_keys(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    session = conn.assigns.current_session

    keys =
      if session.device_id do
        Encryption.get_workspace_encrypted_keys(workspace_id, user_id, session.device_id)
      else
        []
      end

    json(conn, %{
      keys:
        Enum.map(keys, fn k ->
          %{
            key_version: k.key_version,
            encrypted_kek: encode_binary(k.encrypted_kek),
            nonce: encode_binary(k.nonce),
            sender_device_id: k.sender_device_id
          }
        end)
    })
  end

  operation(:create_kek_backup,
    summary: "Create a KEK backup",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Backup params", "application/json", Schemas.CreateKekBackupRequest},
    responses: [
      created: {"Backup created", "application/json", Schemas.OkResponse},
      not_found: {"Workspace not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Version mismatch", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_kek_backup(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id

    workspace = Workspaces.get_workspace(workspace_id)

    active_kek_version =
      cond do
        workspace == nil ->
          nil

        workspace.current_kek_version > 0 ->
          workspace.current_kek_version

        true ->
          # Initial backfill: derive from max active workspace_encrypted_keys
          Encryption.get_max_active_kek_version(workspace_id)
      end

    key_version = params["key_version"]

    cond do
      workspace == nil ->
        conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

      active_kek_version != nil and key_version != active_kek_version ->
        conn |> put_status(:conflict) |> json(%{error: "key_version_mismatch"})

      true ->
        # Set current_kek_version on first backup if not yet set
        if workspace.current_kek_version == 0 and active_kek_version != nil do
          Workspaces.update_current_kek_version(workspace_id, active_kek_version)
        end

        case Encryption.create_workspace_kek_backup(%{
               workspace_id: workspace_id,
               user_id: user_id,
               key_version: key_version,
               encrypted_kek: decode_binary!(params["encrypted_kek"]),
               nonce: decode_binary!(params["nonce"]),
               is_active: true
             }) do
          {:ok, _} ->
            conn |> put_status(:created) |> json(%{ok: true})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "invalid_backup", details: format_errors(changeset)})
        end
    end
  end

  operation(:get_kek_backup,
    summary: "Get active KEK backup",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"KEK backup", "application/json", Schemas.KekBackupResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_kek_backup(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    case Encryption.get_active_kek_backup(workspace_id, user_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      backup ->
        json(conn, %{
          key_version: backup.key_version,
          encrypted_kek: encode_binary(backup.encrypted_kek),
          nonce: encode_binary(backup.nonce)
        })
    end
  end

  operation(:setup_complete,
    summary: "Mark encryption setup as complete",
    responses: [
      ok: {"Setup complete", "application/json", Schemas.OkResponse}
    ]
  )

  def setup_complete(conn, _params) do
    user_id = conn.assigns.current_user_id
    Accounts.update_encryption_setup(user_id)
    json(conn, %{ok: true})
  end

  defp decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end

  defp format_errors(_), do: %{}
end
