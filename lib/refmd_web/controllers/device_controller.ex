defmodule RefMDWeb.DeviceController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Accounts
  alias RefMDWeb.{CryptoValidation, DeviceEventsController, Schemas}

  operation(:bootstrap,
    summary: "Bootstrap first device (first device only)",
    request_body: {"Bootstrap params", "application/json", Schemas.BootstrapDeviceRequest},
    responses: [
      created: {"Bootstrapped device", "application/json", Schemas.CreatePendingDeviceResponse},
      conflict: {"Already has devices", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec bootstrap(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def bootstrap(conn, params) do
    user_id = conn.assigns.current_user_id
    identity_signing_public_key = decode_binary!(params["identity_signing_public_key"])
    ecdh_public_key = decode_binary!(params["device_ecdh_public_key"])
    signing_public_key = decode_binary!(params["device_signing_public_key"])
    client_nonce = decode_binary!(params["client_nonce"])
    identity_signature = decode_binary!(params["identity_signature"])

    stored_identity = RefMD.Encryption.get_user_identity_public_key(user_id)

    with :ok <- validate_identity_key(stored_identity, identity_signing_public_key),
         :ok <- validate_device_keys(ecdh_public_key, signing_public_key, client_nonce) do
      if Accounts.user_has_any_device_records?(user_id) do
        conn |> put_status(:conflict) |> json(%{error: "already_has_devices"})
      else
        bootstrap_first_device(
          conn,
          params,
          user_id,
          ecdh_public_key,
          signing_public_key,
          client_nonce,
          identity_signature
        )
      end
    else
      {:error, error} ->
        {status, msg} = device_validation_error_response(error)
        conn |> put_status(status) |> json(%{error: msg})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  defp bootstrap_first_device(
         conn,
         params,
         user_id,
         ecdh_public_key,
         signing_public_key,
         client_nonce,
         identity_signature
       ) do
    case Accounts.bootstrap_first_device(
           %{
             user_id: user_id,
             name: params["name"],
             device_type: params["device_type"],
             ecdh_public_key: ecdh_public_key,
             signing_public_key: signing_public_key,
             client_nonce: client_nonce
           },
           identity_signature
         ) do
      {:ok, device} ->
        conn
        |> put_status(:created)
        |> json(%{device_id: device.id, status: "approved"})

      {:error, :already_has_devices} ->
        conn |> put_status(:conflict) |> json(%{error: "already_has_devices"})

      {:error, :invalid_signature} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_signature"})

      {:error, _} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "bootstrap_failed"})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:create_pending,
    summary: "Create a pending device (2nd+ devices only)",
    request_body: {"Device params", "application/json", Schemas.CreatePendingDeviceRequest},
    responses: [
      created: {"Pending device", "application/json", Schemas.CreatePendingDeviceResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create_pending(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_pending(conn, params) do
    user_id = conn.assigns.current_user_id
    ecdh_public_key = decode_binary!(params["device_ecdh_public_key"])
    signing_public_key = decode_binary!(params["device_signing_public_key"])
    client_nonce = decode_binary!(params["client_nonce"])
    identity_signing_public_key = decode_binary!(params["identity_signing_public_key"])

    stored_identity = RefMD.Encryption.get_user_identity_public_key(user_id)

    with :ok <- validate_identity_key(stored_identity, identity_signing_public_key),
         :ok <- validate_device_keys(ecdh_public_key, signing_public_key, client_nonce) do
      if Accounts.user_has_any_device_records?(user_id) do
        create_pending_device(
          conn,
          params,
          user_id,
          ecdh_public_key,
          signing_public_key,
          client_nonce
        )
      else
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "use_bootstrap_for_first_device"})
      end
    else
      {:error, error} ->
        {status, msg} = device_validation_error_response(error)
        conn |> put_status(status) |> json(%{error: msg})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  defp create_pending_device(
         conn,
         params,
         user_id,
         ecdh_public_key,
         signing_public_key,
         client_nonce
       ) do
    ua = get_req_header(conn, "user-agent") |> List.first() || ""
    session = conn.assigns.current_session

    case Accounts.replace_user_pending_device(user_id, session.id, %{
           user_id: user_id,
           name: params["name"] || device_name_from_ua(ua),
           device_type: params["device_type"] || device_type_from_ua(ua),
           ecdh_public_key: ecdh_public_key,
           signing_public_key: signing_public_key,
           client_nonce: client_nonce,
           ip_address: to_string(:inet_parse.ntoa(conn.remote_ip))
         }) do
      {:ok, %{removed_ids: removed_ids, pending: pending}} ->
        for removed_id <- removed_ids do
          DeviceEventsController.broadcast_pending_device_removed(user_id, removed_id)
        end

        DeviceEventsController.broadcast_pending_device_created(user_id, pending)

        conn
        |> put_status(:created)
        |> json(%{device_id: pending.id, status: "pending"})

      {:error, _step, changeset, _} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_device", details: format_errors(changeset)})
    end
  end

  operation(:list_pending,
    summary: "List pending devices for current user",
    responses: [
      ok: {"Pending devices", "application/json", Schemas.PendingDevicesResponse}
    ]
  )

  @spec list_pending(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def list_pending(conn, _params) do
    user_id = conn.assigns.current_user_id
    pending_devices = Accounts.get_user_pending_devices(user_id)

    json(conn, %{
      devices:
        Enum.map(pending_devices, fn pd ->
          %{
            id: pd.id,
            name: pd.name,
            device_type: pd.device_type,
            ecdh_public_key: encode_binary(pd.ecdh_public_key),
            signing_public_key: encode_binary(pd.signing_public_key),
            client_nonce: encode_binary(pd.client_nonce),
            ip_address: pd.ip_address,
            created_at: pd.created_at,
            expires_at: pd.expires_at
          }
        end)
    })
  end

  operation(:reject_pending,
    summary: "Reject (delete) a pending device",
    parameters: [
      id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Rejection result", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec reject_pending(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def reject_pending(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Accounts.get_valid_pending_device(id) do
      %{user_id: ^user_id} ->
        Accounts.delete_pending_device(id)
        DeviceEventsController.broadcast_pending_device_removed(user_id, id)
        DeviceEventsController.broadcast_pending_rejected(user_id, id)
        json(conn, %{ok: true})

      _ ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:get_pending_status,
    summary: "Get pending device status (polling fallback for SSE)",
    parameters: [
      id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Status", "application/json", Schemas.PendingDeviceStatusResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_pending_status(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_pending_status(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Accounts.get_pending_device_status(user_id, id) do
      {:ok, status} -> json(conn, %{status: status})
      {:error, :not_found} -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:approve,
    summary: "Approve a pending device",
    parameters: [
      id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Approval params", "application/json", Schemas.ApproveDeviceRequest},
    responses: [
      ok: {"Approved device", "application/json", Schemas.ApproveDeviceResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Approval failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec approve(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def approve(conn, %{"id" => id} = params) do
    user_id = conn.assigns.current_user_id

    case Accounts.get_valid_pending_device(id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      %{user_id: ^user_id} = pending ->
        approve_owned_pending_device(conn, pending, id, params)

      _ ->
        conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:list,
    summary: "List active devices for current user",
    responses: [
      ok: {"Devices", "application/json", Schemas.DevicesResponse}
    ]
  )

  @spec list(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def list(conn, _params) do
    user_id = conn.assigns.current_user_id
    devices = Accounts.get_user_devices(user_id)

    json(conn, %{
      devices:
        Enum.map(devices, fn d ->
          %{
            id: d.id,
            name: d.name,
            device_type: d.device_type,
            ecdh_public_key: encode_binary(d.ecdh_public_key),
            signing_public_key: encode_binary(d.signing_public_key),
            client_nonce: encode_binary(d.client_nonce),
            identity_signature: encode_binary(d.identity_signature),
            last_seen_at: d.last_seen_at,
            created_at: d.created_at
          }
        end)
    })
  end

  operation(:revoke,
    summary: "Revoke a device",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Revocation params", "application/json", Schemas.RevokeDeviceRequest},
    responses: [
      ok: {"Revocation result", "application/json", Schemas.RevokeDeviceResponse},
      bad_request: {"Bad request", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec revoke(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def revoke(conn, %{"device_id" => device_id} = params) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]
    revocation_mode = params["revocation_mode"] || "security"

    cond do
      revocation_mode not in ~w(security retire) ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_revocation_mode"})

      device_id == pop_device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "cannot_revoke_current_device"})

      not Accounts.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      not is_integer(params["revoked_at"]) ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_revoked_at"})

      true ->
        identity_signature = decode_binary!(params["identity_signature"])
        revoked_at_ms = params["revoked_at"]

        with true <-
               Accounts.verify_revocation_signature(
                 user_id,
                 device_id,
                 revocation_mode,
                 pop_device_id,
                 revoked_at_ms,
                 identity_signature
               ),
             {:ok, result} <-
               Accounts.revoke_device(
                 user_id,
                 device_id,
                 pop_device_id,
                 revocation_mode,
                 identity_signature,
                 revoked_at_ms
               ) do
          json(conn, %{
            revoked_device_id: device_id,
            revocation_mode: revocation_mode,
            workspaces_needing_kek_rotation:
              Enum.map(result.workspaces_needing_kek_rotation, fn ws ->
                %{workspace_id: ws.workspace_id, current_kek_version: ws.current_kek_version}
              end)
          })
        else
          false ->
            conn |> put_status(:forbidden) |> json(%{error: "invalid_signature"})

          {:error, _} ->
            conn |> put_status(:unprocessable_entity) |> json(%{error: "revocation_failed"})
        end
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
  end

  operation(:rename,
    summary: "Rename a device",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Rename params", "application/json", Schemas.RenameDeviceRequest},
    responses: [
      ok: {"Renamed device", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec rename(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def rename(conn, %{"device_id" => device_id} = params) do
    user_id = conn.assigns.current_user_id
    name = params["name"]

    case Accounts.rename_device(user_id, device_id, name) do
      {:ok, _device} ->
        json(conn, %{ok: true})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_name", details: format_errors(changeset)})
    end
  end

  defp validate_identity_key(nil, _identity_signing_public_key) do
    {:error, :identity_key_not_found}
  end

  defp validate_identity_key(stored_identity, identity_signing_public_key) do
    if identity_signing_public_key == stored_identity.signing_public_key do
      :ok
    else
      {:error, :identity_signing_public_key_mismatch}
    end
  end

  defp validate_device_keys(ecdh_public_key, signing_public_key, client_nonce) do
    cond do
      byte_size(ecdh_public_key) != 32 ->
        {:error, :invalid_ecdh_public_key_size}

      not CryptoValidation.valid_x25519_public_key?(ecdh_public_key) ->
        {:error, :invalid_ecdh_public_key}

      byte_size(signing_public_key) != 32 ->
        {:error, :invalid_signing_public_key_size}

      not CryptoValidation.valid_ed25519_public_key?(signing_public_key) ->
        {:error, :invalid_signing_public_key}

      byte_size(client_nonce) != 16 ->
        {:error, :invalid_client_nonce_size}

      true ->
        :ok
    end
  end

  defp device_validation_error_response(error) do
    {:unprocessable_entity, Atom.to_string(error)}
  end

  defp approve_owned_pending_device(conn, pending, id, params) do
    identity_signature = decode_binary!(params["identity_signature"])
    session = conn.assigns.current_session

    if session.is_recovery and session.pending_device_id != id do
      conn |> put_status(:forbidden) |> json(%{error: "recovery_self_approval_only"})
    else
      case Accounts.approve_pending_device(pending, identity_signature,
             is_recovery: session.is_recovery
           ) do
        {:ok, device} ->
          json(conn, %{
            device: %{
              id: device.id,
              name: device.name,
              device_type: device.device_type
            }
          })

        {:error, _} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "approval_failed"})
      end
    end
  end

  defp decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  defp decode_binary!(_), do: raise(ArgumentError, "missing required binary field")

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)

  defp device_name_from_ua(ua) do
    cond do
      String.contains?(ua, "Chrome") -> "Chrome"
      String.contains?(ua, "Firefox") -> "Firefox"
      String.contains?(ua, "Safari") -> "Safari"
      true -> "Browser"
    end
  end

  defp device_type_from_ua(ua) do
    if Regex.match?(~r/Mobi|Android/i, ua), do: "mobile", else: "desktop"
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end
end
