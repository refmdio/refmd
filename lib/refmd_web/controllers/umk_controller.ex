defmodule RefMDWeb.UmkController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Devices
  alias RefMD.Security
  alias RefMDWeb.Payloads.DeviceIdentity
  alias RefMDWeb.Schemas

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
    sender_device_id = conn.assigns.rrp_device_id

    with :ok <- validate_sender_device_match(sender_device_id, params["sender_device_id"]),
         :ok <- validate_distribution_target(user_id, target_device_id) do
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

  def get_umk(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id
    rrp_device_id = conn.assigns[:rrp_device_id]

    cond do
      rrp_device_id != nil and rrp_device_id != device_id ->
        conn |> put_status(:forbidden) |> json(%{error: "device_mismatch"})

      not Devices.user_owns_active_device?(user_id, device_id) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
        respond_with_umk(conn, user_id, device_id)
    end
  end

  # --- Private helpers ---

  defp validate_sender_device_match(rrp_device_id, sender_device_id) do
    if rrp_device_id != nil and sender_device_id != nil and sender_device_id != rrp_device_id do
      {:error, :forbidden, "sender_device_id_mismatch"}
    else
      :ok
    end
  end

  defp validate_distribution_target(user_id, device_id) do
    cond do
      Devices.user_owns_active_device?(user_id, device_id) ->
        :ok

      match?(%{user_id: ^user_id}, Devices.get_valid_device_registration(device_id)) ->
        :ok

      true ->
        {:error, :forbidden, "invalid_device"}
    end
  end

  defp execute_distribute_umk(conn, user_id, target_device_id, sender_device_id, params) do
    with {:ok, sender_device} <- fetch_active_device(user_id, sender_device_id),
         {:ok, target_device} <- fetch_pending_delivery_target(user_id, target_device_id) do
      Devices.finalize_pending_delivery_from_params(
        user_id,
        target_device_id,
        sender_device,
        target_device,
        params
      )
    end
    |> case do
      {:ok, _} ->
        Security.record_registration_approved(user_id, target_device_id)
        conn |> put_status(:created) |> json(%{ok: true})

      {:error, %Ecto.Changeset{} = changeset} when changeset.errors != [] ->
        handle_umk_changeset_error(conn, changeset)

      {:error, :invalid_key_directory} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})

      {:error, :missing_key_directory} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_key_directory"})

      {:error, :invalid_initial_key_delivery} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_initial_key_delivery"})

      {:error, :invalid_initial_ake_prekey} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_initial_ake_prekey"})

      {:error, :initial_ake_prekey_reused} ->
        conn |> put_status(:conflict) |> json(%{error: "initial_ake_prekey_reused"})

      {:error, :invalid_device} ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})
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

  defp respond_with_umk(conn, user_id, device_id) do
    case Devices.get_device_encrypted_umk(user_id, device_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      umk_data ->
        format_umk_response(conn, umk_data)
    end
  end

  defp format_umk_response(conn, umk_data) do
    case Devices.get_device(umk_data.sender_device_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "sender_device_not_found"})

      sender ->
        json(
          conn,
          %{
            sender_device_id: umk_data.sender_device_id,
            initial_ake: umk_data.initial_ake,
            initial_key_delivery: umk_data.initial_key_delivery,
            initial_kek_deliveries: umk_data.initial_kek_deliveries,
            device_state_delivery: umk_data.device_state_delivery
          }
          |> Map.merge(DeviceIdentity.sender_fields(sender))
        )
    end
  end

  defp fetch_active_device(user_id, device_id) when is_binary(device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil, identity_wipe_required_at: nil} = device ->
        {:ok, device}

      _ ->
        {:error, :invalid_device}
    end
  end

  defp fetch_active_device(_user_id, _device_id), do: {:error, :invalid_device}

  defp fetch_pending_delivery_target(user_id, device_id) when is_binary(device_id) do
    case Devices.get_valid_device_registration(device_id) do
      %{user_id: ^user_id, approval_signature: signature} = registration
      when is_map(signature) ->
        {:ok, registration}

      _ ->
        {:error, :invalid_device}
    end
  end
end
