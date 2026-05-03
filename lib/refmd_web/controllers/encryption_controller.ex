defmodule RefMDWeb.EncryptionController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Devices, Encryption, Users, Workspaces}
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

  @spec create_workspace_key(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_workspace_key(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]
    sender_device_id = pop_device_id || params["sender_device_id"]

    with :ok <- validate_sender_device_match(pop_device_id, params["sender_device_id"]),
         {:ok, workspace} <- fetch_workspace(workspace_id),
         :ok <- require_membership(workspace_id, user_id),
         :ok <- validate_device_ownership(user_id, params["device_id"]),
         :ok <- validate_key_version_range(params["key_version"], workspace, user_id) do
      execute_create_workspace_key(conn, workspace, %{
        workspace_id: workspace_id,
        user_id: user_id,
        device_id: params["device_id"],
        key_version: params["key_version"],
        sender_device_id: sender_device_id,
        encrypted_kek: decode_binary!(params["encrypted_kek"]),
        nonce: decode_binary!(params["nonce"]),
        is_active: Map.get(params, "is_active", true)
      })
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:get_workspace_keys,
    summary: "Get workspace encryption keys",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      device_id: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Workspace keys", "application/json", Schemas.WorkspaceKeysResponse},
      bad_request: {"Bad request", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_workspace_keys(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_workspace_keys(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    device_id = params["device_id"]
    pop_device_id = conn.assigns[:pop_device_id]

    with :ok <- require_device_id(device_id),
         :ok <- validate_pop_device_match(pop_device_id, device_id),
         :ok <- validate_device_owned(user_id, device_id),
         :ok <- require_membership(workspace_id, user_id) do
      workspace = Workspaces.get_workspace(workspace_id)
      keys = Encryption.get_workspace_encrypted_keys(workspace_id, user_id, device_id)

      if keys == [] do
        conn
        |> put_status(:not_found)
        |> json(%{
          error: "not_found",
          details: %{current_kek_version: workspace && workspace.current_kek_version}
        })
      else
        json(conn, %{
          current_kek_version: workspace && workspace.current_kek_version,
          keys: Enum.map(keys, &format_workspace_key/1)
        })
      end
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
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

  @spec create_kek_backup(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_kek_backup(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    key_version = params["key_version"]

    with {:ok, workspace} <- fetch_workspace(workspace_id, "workspace_not_found"),
         :ok <- require_membership(workspace_id, user_id),
         {:ok, active_kek_version} <- resolve_active_kek_version(workspace),
         :ok <- validate_kek_backup_version(key_version, active_kek_version, workspace, user_id),
         :ok <- validate_user_has_active_kek(workspace, workspace_id, user_id) do
      execute_create_kek_backup(conn, workspace, workspace_id, active_kek_version, %{
        workspace_id: workspace_id,
        user_id: user_id,
        key_version: key_version,
        encrypted_kek: decode_binary!(params["encrypted_kek"]),
        nonce: decode_binary!(params["nonce"]),
        is_active: true
      })
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:get_kek_backup,
    summary: "Get KEK backup (active or by version)",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      key_version: [in: :query, type: :integer, required: false]
    ],
    responses: [
      ok: {"KEK backup", "application/json", Schemas.KekBackupResponse},
      forbidden: {"Not a member", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_kek_backup(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_kek_backup(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id

    case require_workspace_crypto_access(workspace_id, user_id) do
      :ok ->
        backup = resolve_kek_backup(workspace_id, user_id, params["key_version"])

        case backup do
          nil ->
            conn |> put_status(:not_found) |> json(%{error: "not_found"})

          b ->
            json(conn, %{
              key_version: b.key_version,
              encrypted_kek: encode_binary(b.encrypted_kek),
              nonce: encode_binary(b.nonce)
            })
        end

      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:workspace_ids,
    summary: "Get workspace IDs for the current user",
    responses: [
      ok: {"Workspace IDs", "application/json", Schemas.WorkspaceIdsResponse}
    ]
  )

  @spec workspace_ids(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def workspace_ids(conn, _params) do
    user_id = conn.assigns.current_user_id
    ids = Workspaces.get_discoverable_workspace_ids(user_id)
    json(conn, %{workspace_ids: ids})
  end

  operation(:setup_complete,
    summary: "Mark encryption setup as complete",
    responses: [
      ok: {"Setup complete", "application/json", Schemas.OkResponse}
    ]
  )

  @spec setup_complete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def setup_complete(conn, _params) do
    user_id = conn.assigns.current_user_id
    workspace_ids = Workspaces.get_user_workspace_ids(user_id)

    cond do
      not Devices.user_has_devices?(user_id) ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "no_device"})

      workspace_ids == [] ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "no_workspace"})

      not Enum.all?(workspace_ids, &Encryption.user_has_active_kek?(&1, user_id)) ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_kek_envelope"})

      not Enum.all?(workspace_ids, fn wid ->
        Encryption.get_active_kek_backup(wid, user_id) != nil
      end) ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_kek_backup"})

      true ->
        Users.update_encryption_setup(user_id)
        json(conn, %{ok: true})
    end
  end

  # --- Validation helpers ---

  defp fetch_workspace(workspace_id, error_key \\ "not_found") do
    case Workspaces.get_workspace(workspace_id) do
      nil -> {:error, :not_found, error_key}
      workspace -> {:ok, workspace}
    end
  end

  defp require_workspace_crypto_access(workspace_id, user_id) do
    cond do
      Workspaces.get_member_role(workspace_id, user_id) == nil ->
        {:error, :forbidden, "not_a_member"}

      Workspaces.guest_user?(user_id) and
          Workspaces.authorize_guest_permission(workspace_id, user_id, "document:read", nil) !=
            :ok ->
        {:error, :forbidden, "permission_denied"}

      true ->
        :ok
    end
  end

  defp require_membership(workspace_id, user_id),
    do: require_workspace_crypto_access(workspace_id, user_id)

  defp validate_sender_device_match(pop_device_id, sender_device_id) do
    if pop_device_id != nil and sender_device_id != nil and sender_device_id != pop_device_id do
      {:error, :forbidden, "sender_device_id_mismatch"}
    else
      :ok
    end
  end

  defp validate_device_ownership(_user_id, nil), do: :ok

  defp validate_device_ownership(user_id, device_id) do
    if Devices.user_owns_active_device?(user_id, device_id) do
      :ok
    else
      {:error, :forbidden, "invalid_device"}
    end
  end

  defp validate_device_owned(user_id, device_id) do
    if Devices.user_owns_active_device?(user_id, device_id) do
      :ok
    else
      {:error, :forbidden, "device_not_owned"}
    end
  end

  defp validate_key_version_range(key_version, workspace, user_id)
       when is_integer(key_version) do
    max = max_allowed_key_version(workspace, user_id, key_version)

    cond do
      key_version < 1 ->
        {:error, :unprocessable_entity, "key_version_must_be_positive"}

      key_version < workspace.min_kek_version ->
        {:error, :unprocessable_entity, "key_version_below_minimum"}

      key_version > max ->
        {:error, :unprocessable_entity, "key_version_too_high"}

      true ->
        :ok
    end
  end

  defp validate_key_version_range(_key_version, _workspace, _user_id), do: :ok

  defp max_allowed_key_version(%{current_kek_version: 0}, _user_id, _key_version), do: 1

  defp max_allowed_key_version(workspace, user_id, key_version) do
    if workspace.needs_kek_rotation and
         workspace.kek_rotation_initiator_user_id == user_id and
         key_version == workspace.current_kek_version + 1 do
      workspace.current_kek_version + 1
    else
      workspace.current_kek_version
    end
  end

  defp require_device_id(device_id) do
    if is_nil(device_id) or device_id == "" do
      {:error, :bad_request, "device_id_required"}
    else
      :ok
    end
  end

  defp validate_pop_device_match(nil, _device_id), do: :ok

  defp validate_pop_device_match(pop_device_id, device_id) do
    if pop_device_id != device_id do
      {:error, :forbidden, "device_mismatch"}
    else
      :ok
    end
  end

  defp resolve_active_kek_version(workspace) do
    if workspace.current_kek_version > 0 do
      {:ok, workspace.current_kek_version}
    else
      case Encryption.get_max_active_kek_version(workspace.id) do
        nil -> {:error, :conflict, "no_active_kek"}
        version -> {:ok, version}
      end
    end
  end

  defp validate_kek_backup_version(key_version, active_kek_version, workspace, user_id) do
    rotation_version_allowed =
      workspace.needs_kek_rotation and
        workspace.kek_rotation_initiator_user_id == user_id and
        key_version == active_kek_version + 1

    if key_version == active_kek_version or rotation_version_allowed do
      :ok
    else
      {:error, :conflict, "key_version_mismatch"}
    end
  end

  defp validate_user_has_active_kek(_workspace, workspace_id, user_id) do
    if Encryption.user_has_active_kek?(workspace_id, user_id) do
      :ok
    else
      {:error, :forbidden, "no_active_kek_for_user"}
    end
  end

  # --- Execution helpers ---

  defp execute_create_workspace_key(conn, workspace, attrs) do
    case Encryption.create_workspace_encrypted_key(attrs) do
      {:ok, key} ->
        handle_workspace_key_created(conn, workspace, key, attrs.key_version)

      {:error, :invalid_sender_device} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_sender_device"})

      {:error, %Ecto.Changeset{} = changeset} ->
        handle_workspace_key_changeset_error(conn, changeset)
    end
  end

  defp handle_workspace_key_created(conn, workspace, key, key_version) do
    if workspace.current_kek_version == 0 and key_version == 1 do
      case Workspaces.initialize_kek_version(key.workspace_id) do
        {1, _} ->
          conn |> put_status(:created) |> json(%{ok: true})

        {0, _} ->
          Encryption.delete_workspace_encrypted_key(
            key.workspace_id,
            key.user_id,
            key.device_id,
            key.key_version
          )

          conn |> put_status(:conflict) |> json(%{error: "key_version_already_exists"})
      end
    else
      conn |> put_status(:created) |> json(%{ok: true})
    end
  end

  defp handle_workspace_key_changeset_error(conn, changeset) do
    if has_unique_constraint_error?(changeset) do
      conn |> put_status(:conflict) |> json(%{error: "key_version_already_exists"})
    else
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "invalid_key", details: format_errors(changeset)})
    end
  end

  defp execute_create_kek_backup(conn, workspace, workspace_id, active_kek_version, attrs) do
    case Encryption.create_workspace_kek_backup(attrs) do
      {:ok, _} ->
        if workspace.current_kek_version == 0 do
          Workspaces.update_current_kek_version(workspace_id, active_kek_version)
        end

        conn |> put_status(:created) |> json(%{ok: true})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_backup", details: format_errors(changeset)})
    end
  end

  defp format_workspace_key(key) do
    sender = if key.sender_device_id, do: Devices.get_device(key.sender_device_id)

    %{
      key_version: key.key_version,
      encrypted_kek: encode_binary(key.encrypted_kek),
      nonce: encode_binary(key.nonce),
      is_active: key.is_active,
      sender_device_id: key.sender_device_id,
      sender_ecdh_public_key: sender && encode_binary(sender.ecdh_public_key),
      sender_signing_public_key: sender && encode_binary(sender.signing_public_key)
    }
  end

  defp resolve_kek_backup(workspace_id, user_id, nil) do
    Encryption.get_active_kek_backup(workspace_id, user_id)
  end

  defp resolve_kek_backup(workspace_id, user_id, ver) when is_binary(ver) do
    case Integer.parse(ver) do
      {int_ver, ""} -> Encryption.get_kek_backup_by_version(workspace_id, user_id, int_ver)
      _ -> nil
    end
  end

  defp resolve_kek_backup(workspace_id, user_id, ver) when is_integer(ver) do
    Encryption.get_kek_backup_by_version(workspace_id, user_id, ver)
  end
end
