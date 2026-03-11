defmodule RefMDWeb.EncryptionController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Devices, Encryption, Users, Workspaces}
  alias RefMDWeb.{DeviceEventsController, Schemas}

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
         :ok <- validate_key_version_range(params["key_version"], workspace) do
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
    summary: "Get active KEK backup",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"KEK backup", "application/json", Schemas.KekBackupResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_kek_backup(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_kek_backup(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    if Workspaces.get_member_role(workspace_id, user_id) == nil do
      conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})
    else
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
  end

  operation(:distribute_umk,
    summary: "Distribute UMK to a device (existing device sends)",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"UMK distribution params", "application/json", Schemas.DistributeUmkRequest},
    responses: [
      created: {"UMK distributed", "application/json", Schemas.OkResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse},
      conflict: {"UMK already distributed", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec distribute_umk(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def distribute_umk(conn, %{"device_id" => target_device_id} = params) do
    user_id = conn.assigns.current_user_id
    sender_device_id = conn.assigns.pop_device_id

    with :ok <- validate_sender_device_match(sender_device_id, params["sender_device_id"]),
         :ok <- validate_active_device_ownership(user_id, target_device_id) do
      execute_distribute_umk(conn, user_id, target_device_id, sender_device_id, params)
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:get_umk,
    summary: "Get distributed UMK for a device",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"UMK data", "application/json", Schemas.GetUmkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_umk(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_umk(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]

    cond do
      pop_device_id != nil and pop_device_id != device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "device_mismatch"})

      not Devices.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
        case Devices.get_device_encrypted_umk(user_id, device_id) do
          nil ->
            conn |> put_status(:not_found) |> json(%{error: "not_found"})

          umk_data ->
            sender = Devices.get_device(umk_data.sender_device_id)

            json(conn, %{
              encrypted_umk: encode_binary(umk_data.encrypted_umk),
              nonce: encode_binary(umk_data.nonce),
              sender_device_id: umk_data.sender_device_id,
              sender_ecdh_public_key: sender && encode_binary(sender.ecdh_public_key),
              sender_signing_public_key: sender && encode_binary(sender.signing_public_key)
            })
        end
    end
  end

  operation(:start_kek_rotation,
    summary: "Start KEK rotation for a workspace (manual trigger)",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Rotation started", "application/json", Schemas.KekRotationStartResponse},
      not_found: {"Workspace not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse},
      conflict: {"Rotation already in progress", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec start_kek_rotation(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def start_kek_rotation(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    base_role = Workspaces.get_member_role(workspace_id, user_id)

    if base_role in ~w(owner admin) do
      case Workspaces.start_kek_rotation(workspace_id, user_id) do
        {:ok, _} ->
          json(conn, %{workspace_id: workspace_id, needs_kek_rotation: true})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

        {:error, :kek_rotation_already_in_progress} ->
          conn |> put_status(:conflict) |> json(%{error: "kek_rotation_already_in_progress"})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  end

  operation(:complete_kek_rotation,
    summary: "Complete KEK rotation for a workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Completion params", "application/json", Schemas.KekRotationCompleteRequest},
    responses: [
      ok: {"Rotation completed", "application/json", Schemas.OkResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Preconditions not met", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec complete_kek_rotation(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def complete_kek_rotation(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    new_kek_version = params["new_kek_version"]

    with {:ok, workspace} <- fetch_workspace(workspace_id, "workspace_not_found"),
         {:ok, base_role} <- fetch_membership(workspace_id, user_id),
         :ok <- require_rotation_in_progress(workspace),
         :ok <- require_rotation_authority(workspace, user_id, base_role) do
      envelope_checks = build_envelope_checks(workspace_id, user_id, new_kek_version)

      Workspaces.complete_kek_rotation(workspace_id, new_kek_version,
        envelope_checks: envelope_checks
      )
      |> handle_rotation_completion(conn)
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:save_member_envelopes,
    summary: "Save member envelopes for KEK rotation",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Member envelopes", "application/json", Schemas.SaveMemberEnvelopesRequest},
    responses: [
      ok: {"Envelopes saved", "application/json", Schemas.OkResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec save_member_envelopes(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def save_member_envelopes(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]
    envelopes = params["envelopes"] || []

    with {:ok, workspace} <- fetch_workspace(workspace_id, "workspace_not_found"),
         {:ok, base_role} <- fetch_membership(workspace_id, user_id),
         :ok <- require_rotation_in_progress(workspace),
         :ok <- require_rotation_authority(workspace, user_id, base_role),
         :ok <- validate_envelope_senders(envelopes, pop_device_id) do
      case Encryption.save_member_envelopes(workspace_id, envelopes) do
        {:ok, _} ->
          json(conn, %{ok: true})

        {:error, _} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "save_failed"})
      end
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:get_member_envelope,
    summary: "Get own member envelope for KEK recovery",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Member envelope", "application/json", Schemas.MemberEnvelopeResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_member_envelope(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_member_envelope(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    if Workspaces.get_member_role(workspace_id, user_id) == nil do
      conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})
    else
      case Encryption.get_member_envelope(workspace_id, user_id) do
        nil ->
          conn |> put_status(:not_found) |> json(%{error: "not_found"})

        envelope ->
          sender = Devices.get_device(envelope.sender_device_id)

          json(conn, %{
            key_version: envelope.key_version,
            sender_device_id: envelope.sender_device_id,
            sender_ecdh_public_key: sender && encode_binary(sender.ecdh_public_key),
            sender_signing_public_key: sender && encode_binary(sender.signing_public_key),
            encrypted_kek: encode_binary(envelope.encrypted_kek),
            nonce: encode_binary(envelope.nonce)
          })
      end
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
    ids = Workspaces.get_user_workspace_ids(user_id)
    json(conn, %{workspace_ids: ids})
  end

  operation(:get_workspace_member_keys,
    summary: "Get Identity ECDH public keys for all workspace members",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Member keys", "application/json", Schemas.WorkspaceMemberKeysResponse},
      forbidden: {"Not a member", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_workspace_member_keys(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_workspace_member_keys(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    if Workspaces.get_member_role(workspace_id, user_id) == nil do
      conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})
    else
      members = Encryption.get_workspace_member_identity_keys(workspace_id)

      json(conn, %{
        members:
          Enum.map(members, fn m ->
            %{
              user_id: m.user_id,
              ecdh_public_key: encode_binary(m.ecdh_public_key)
            }
          end)
      })
    end
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

  # --- Shared validation helpers ---

  defp fetch_workspace(workspace_id, error_key \\ "not_found") do
    case Workspaces.get_workspace(workspace_id) do
      nil -> {:error, :not_found, error_key}
      workspace -> {:ok, workspace}
    end
  end

  defp require_membership(workspace_id, user_id) do
    if Workspaces.get_member_role(workspace_id, user_id) == nil do
      {:error, :forbidden, "not_a_member"}
    else
      :ok
    end
  end

  defp fetch_membership(workspace_id, user_id) do
    case Workspaces.get_member_role(workspace_id, user_id) do
      nil -> {:error, :forbidden, "not_a_member"}
      role -> {:ok, role}
    end
  end

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

  defp validate_active_device_ownership(user_id, device_id) do
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

  defp validate_key_version_range(key_version, workspace) when is_integer(key_version) do
    cond do
      key_version < 1 ->
        {:error, :unprocessable_entity, "key_version_must_be_positive"}

      key_version < workspace.min_kek_version ->
        {:error, :unprocessable_entity, "key_version_below_minimum"}

      key_version > workspace.current_kek_version + 1 ->
        {:error, :unprocessable_entity, "key_version_too_high"}

      true ->
        :ok
    end
  end

  defp validate_key_version_range(_key_version, _workspace), do: :ok

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

  defp require_rotation_in_progress(workspace) do
    if workspace.needs_kek_rotation do
      :ok
    else
      {:error, :unprocessable_entity, "not_in_rotation"}
    end
  end

  defp require_rotation_authority(workspace, user_id, base_role) do
    if workspace.kek_rotation_initiator_user_id == user_id or base_role in ~w(owner admin) do
      :ok
    else
      {:error, :forbidden, "forbidden"}
    end
  end

  defp validate_envelope_senders(envelopes, pop_device_id) do
    has_invalid =
      Enum.any?(envelopes, fn env ->
        env["sender_device_id"] != pop_device_id
      end)

    if has_invalid do
      {:error, :forbidden, "sender_device_id_mismatch"}
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

  defp execute_distribute_umk(conn, user_id, target_device_id, sender_device_id, params) do
    case Devices.create_device_encrypted_umk(%{
           user_id: user_id,
           device_id: target_device_id,
           sender_device_id: sender_device_id,
           encrypted_umk: decode_binary!(params["encrypted_umk"]),
           nonce: decode_binary!(params["nonce"])
         }) do
      {:ok, _} ->
        DeviceEventsController.broadcast_registration_approved(user_id, target_device_id)
        conn |> put_status(:created) |> json(%{ok: true})

      {:error, %Ecto.Changeset{} = changeset} when changeset.errors != [] ->
        handle_umk_changeset_error(conn, changeset)
    end
  end

  defp handle_umk_changeset_error(conn, changeset) do
    if has_unique_constraint_error?(changeset) do
      conn |> put_status(:conflict) |> json(%{error: "umk_already_distributed"})
    else
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "invalid_umk", details: format_errors(changeset)})
    end
  end

  defp format_workspace_key(key) do
    sender = if key.sender_device_id, do: Devices.get_device(key.sender_device_id)

    %{
      key_version: key.key_version,
      encrypted_kek: encode_binary(key.encrypted_kek),
      nonce: encode_binary(key.nonce),
      sender_device_id: key.sender_device_id,
      sender_ecdh_public_key: sender && encode_binary(sender.ecdh_public_key),
      sender_signing_public_key: sender && encode_binary(sender.signing_public_key)
    }
  end

  defp build_envelope_checks(workspace_id, user_id, new_kek_version) do
    fn ->
      cond do
        not Encryption.all_user_devices_have_key?(workspace_id, user_id, new_kek_version) ->
          {:error, :missing_device_envelopes}

        not Encryption.all_members_have_envelope?(workspace_id, new_kek_version) ->
          {:error, :missing_member_envelopes}

        true ->
          :ok
      end
    end
  end

  defp handle_rotation_completion(result, conn) do
    case result do
      :ok ->
        json(conn, %{ok: true})

      {:error, :not_in_rotation} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "not_in_rotation"})

      {:error, :version_not_monotonic} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "version_not_monotonic"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

      {:error, :missing_device_envelopes} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_device_envelopes"})

      {:error, :missing_member_envelopes} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_member_envelopes"})
    end
  end

  # --- Encoding / error helpers ---

  defp decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  defp decode_binary!(_), do: raise(ArgumentError, "missing required binary field")

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end

  defp has_unique_constraint_error?(changeset) do
    Enum.any?(changeset.errors, fn {_field, {_msg, opts}} ->
      Keyword.get(opts, :constraint) == :unique
    end)
  end
end
