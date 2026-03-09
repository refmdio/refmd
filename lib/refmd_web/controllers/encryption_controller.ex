defmodule RefMDWeb.EncryptionController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Accounts, Encryption, Workspaces}
  alias RefMDWeb.{Schemas, DeviceEventsController}

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
    device_id = params["device_id"]
    pop_device_id = conn.assigns[:pop_device_id]
    sender_device_id = pop_device_id || params["sender_device_id"]

    workspace = Workspaces.get_workspace(workspace_id)
    key_version = params["key_version"]

    cond do
      pop_device_id != nil and params["sender_device_id"] != nil and
          params["sender_device_id"] != pop_device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "sender_device_id_mismatch"})

      workspace == nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      Workspaces.get_member_role(workspace_id, user_id) == nil ->
        conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})

      device_id != nil and not Accounts.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      is_integer(key_version) and key_version < workspace.min_kek_version ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "key_version_below_minimum"})

      is_integer(key_version) and key_version > workspace.current_kek_version + 1 ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "key_version_too_high"})

      true ->
        case Encryption.create_workspace_encrypted_key(%{
               workspace_id: workspace_id,
               user_id: user_id,
               device_id: device_id,
               key_version: params["key_version"],
               sender_device_id: sender_device_id,
               encrypted_kek: decode_binary!(params["encrypted_kek"]),
               nonce: decode_binary!(params["nonce"]),
               is_active: params["is_active"] || true
             }) do
          {:ok, key} ->
            if workspace.current_kek_version == 0 and params["key_version"] == 1 do
              case Workspaces.initialize_kek_version(workspace_id) do
                {1, _} ->
                  conn |> put_status(:created) |> json(%{ok: true})

                {0, _} ->
                  # Race: another device already initialized — delete to prevent fork
                  Encryption.delete_workspace_encrypted_key(
                    key.workspace_id, key.user_id, key.device_id, key.key_version
                  )
                  conn |> put_status(:conflict) |> json(%{error: "key_version_already_exists"})
              end
            else
              conn |> put_status(:created) |> json(%{ok: true})
            end

          {:error, :invalid_sender_device} ->
            conn |> put_status(:forbidden) |> json(%{error: "invalid_sender_device"})

          {:error, %Ecto.Changeset{} = changeset} ->
            if has_unique_constraint_error?(changeset) do
              conn |> put_status(:conflict) |> json(%{error: "key_version_already_exists"})
            else
              conn
              |> put_status(:unprocessable_entity)
              |> json(%{error: "invalid_key", details: format_errors(changeset)})
            end
        end
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
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_workspace_keys(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    device_id = params["device_id"]
    pop_device_id = conn.assigns[:pop_device_id]

    cond do
      is_nil(device_id) or device_id == "" ->
        conn |> put_status(:bad_request) |> json(%{error: "device_id_required"})

      pop_device_id != nil and pop_device_id != device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "device_mismatch"})

      not Accounts.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "device_not_owned"})

      Workspaces.get_member_role(workspace_id, user_id) == nil ->
        conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})

      true ->
        workspace = Workspaces.get_workspace(workspace_id)
        keys = Encryption.get_workspace_encrypted_keys(workspace_id, user_id, device_id)

        json(conn, %{
          current_kek_version: workspace && workspace.current_kek_version,
          keys:
            Enum.map(keys, fn k ->
              sender = if k.sender_device_id, do: Accounts.get_device(k.sender_device_id)

              %{
                key_version: k.key_version,
                encrypted_kek: encode_binary(k.encrypted_kek),
                nonce: encode_binary(k.nonce),
                sender_device_id: k.sender_device_id,
                sender_ecdh_public_key: sender && encode_binary(sender.ecdh_public_key),
                sender_signing_public_key: sender && encode_binary(sender.signing_public_key)
              }
            end)
        })
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

      Workspaces.get_member_role(workspace_id, user_id) == nil ->
        conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})

      active_kek_version == nil ->
        conn |> put_status(:conflict) |> json(%{error: "no_active_kek"})

      key_version != active_kek_version and
          not (workspace.needs_kek_rotation and
                 workspace.kek_rotation_initiator_user_id == user_id and
                 key_version == active_kek_version + 1) ->
        conn |> put_status(:conflict) |> json(%{error: "key_version_mismatch"})

      workspace.current_kek_version > 0 and
          not Encryption.user_has_active_kek?(workspace_id, user_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "no_active_kek_for_user"})

      true ->
        case Encryption.create_workspace_kek_backup(%{
               workspace_id: workspace_id,
               user_id: user_id,
               key_version: key_version,
               encrypted_kek: decode_binary!(params["encrypted_kek"]),
               nonce: decode_binary!(params["nonce"]),
               is_active: true
             }) do
          {:ok, _} ->
            # Set current_kek_version on first backup if not yet set (after successful write)
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

  def distribute_umk(conn, %{"device_id" => target_device_id} = params) do
    user_id = conn.assigns.current_user_id
    sender_device_id = conn.assigns.pop_device_id

    cond do
      params["sender_device_id"] != nil and params["sender_device_id"] != sender_device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "sender_device_id_mismatch"})

      not Accounts.user_owns_active_device?(user_id, target_device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
      case Encryption.create_device_encrypted_umk(%{
             user_id: user_id,
             device_id: target_device_id,
             sender_device_id: sender_device_id,
             encrypted_umk: decode_binary!(params["encrypted_umk"]),
             nonce: decode_binary!(params["nonce"])
           }) do
        {:ok, _} ->
          DeviceEventsController.broadcast_pending_approved(user_id, target_device_id)
          conn |> put_status(:created) |> json(%{ok: true})

        {:error, %Ecto.Changeset{} = changeset} when changeset.errors != [] ->
          if has_unique_constraint_error?(changeset) do
            conn |> put_status(:conflict) |> json(%{error: "umk_already_distributed"})
          else
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "invalid_umk", details: format_errors(changeset)})
          end

      end
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

  def get_umk(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]

    cond do
      pop_device_id != nil and pop_device_id != device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "device_mismatch"})

      not Accounts.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
        case Encryption.get_device_encrypted_umk(user_id, device_id) do
          nil ->
            conn |> put_status(:not_found) |> json(%{error: "not_found"})

          umk_data ->
            sender = Accounts.get_device(umk_data.sender_device_id)

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

  def start_kek_rotation(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    base_role = Workspaces.get_member_role(workspace_id, user_id)

    unless base_role in ~w(owner admin) do
      conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    else
      case Workspaces.start_kek_rotation(workspace_id, user_id) do
        {:ok, _} ->
          json(conn, %{workspace_id: workspace_id, needs_kek_rotation: true})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

        {:error, :kek_rotation_already_in_progress} ->
          conn |> put_status(:conflict) |> json(%{error: "kek_rotation_already_in_progress"})
      end
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

  def complete_kek_rotation(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    new_kek_version = params["new_kek_version"]

    workspace = Workspaces.get_workspace(workspace_id)
    base_role = Workspaces.get_member_role(workspace_id, user_id)

    cond do
      workspace == nil ->
        conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

      base_role == nil ->
        conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})

      not workspace.needs_kek_rotation ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "not_in_rotation"})

      workspace.kek_rotation_initiator_user_id != user_id and base_role not in ~w(owner admin) ->
        conn |> put_status(:forbidden) |> json(%{error: "forbidden"})

      true ->
        envelope_checks = fn ->
          cond do
            not Encryption.all_user_devices_have_key?(workspace_id, user_id, new_kek_version) ->
              {:error, :missing_device_envelopes}

            not Encryption.all_members_have_envelope?(workspace_id, new_kek_version) ->
              {:error, :missing_member_envelopes}

            true ->
              :ok
          end
        end

        case Workspaces.complete_kek_rotation(workspace_id, new_kek_version,
               envelope_checks: envelope_checks
             ) do
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

  def save_member_envelopes(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id

    workspace = Workspaces.get_workspace(workspace_id)
    base_role = Workspaces.get_member_role(workspace_id, user_id)

    cond do
      workspace == nil ->
        conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

      base_role == nil ->
        conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})

      not workspace.needs_kek_rotation ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "not_in_rotation"})

      workspace.kek_rotation_initiator_user_id != user_id and base_role not in ~w(owner admin) ->
        conn |> put_status(:forbidden) |> json(%{error: "forbidden"})

      true ->
        pop_device_id = conn.assigns[:pop_device_id]
        envelopes = params["envelopes"] || []

        invalid_sender =
          Enum.any?(envelopes, fn env ->
            env["sender_device_id"] != pop_device_id
          end)

        if invalid_sender do
          conn |> put_status(:forbidden) |> json(%{error: "sender_device_id_mismatch"})
        else
          case Encryption.save_member_envelopes(workspace_id, envelopes) do
            {:ok, _} ->
              json(conn, %{ok: true})

            {:error, _} ->
              conn |> put_status(:unprocessable_entity) |> json(%{error: "save_failed"})
          end
        end
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

  def get_member_envelope(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    if Workspaces.get_member_role(workspace_id, user_id) == nil do
      conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})
    else
      case Encryption.get_member_envelope(workspace_id, user_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      envelope ->
        sender = Accounts.get_device(envelope.sender_device_id)

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

  def workspace_ids(conn, _params) do
    user_id = conn.assigns.current_user_id
    ids = Workspaces.get_user_workspace_ids(user_id)
    json(conn, %{workspace_ids: ids})
  end

  operation(:setup_complete,
    summary: "Mark encryption setup as complete",
    responses: [
      ok: {"Setup complete", "application/json", Schemas.OkResponse}
    ]
  )

  def setup_complete(conn, _params) do
    user_id = conn.assigns.current_user_id
    workspace_ids = Workspaces.get_user_workspace_ids(user_id)

    cond do
      not Accounts.user_has_devices?(user_id) ->
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
        Accounts.update_encryption_setup(user_id)
        json(conn, %{ok: true})
    end
  end

  defp decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  defp decode_binary!(_), do: raise(ArgumentError, "missing required binary field")

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end

  defp format_errors(_), do: %{}

  defp has_unique_constraint_error?(changeset) do
    Enum.any?(changeset.errors, fn {_field, {_msg, opts}} ->
      Keyword.get(opts, :constraint) == :unique
    end)
  end
end
