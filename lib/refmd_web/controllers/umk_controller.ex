defmodule RefMDWeb.UmkController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Devices
  alias RefMDWeb.{DeviceEventsController, Schemas}

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
         :ok <- validate_device_ownership(user_id, target_device_id) do
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
        respond_with_umk(conn, user_id, device_id)
    end
  end

  # --- Private helpers ---

  defp validate_sender_device_match(pop_device_id, sender_device_id) do
    if pop_device_id != nil and sender_device_id != nil and sender_device_id != pop_device_id do
      {:error, :forbidden, "sender_device_id_mismatch"}
    else
      :ok
    end
  end

  defp validate_device_ownership(user_id, device_id) do
    if Devices.user_owns_active_device?(user_id, device_id) do
      :ok
    else
      {:error, :forbidden, "invalid_device"}
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
        json(conn, %{
          encrypted_umk: encode_binary(umk_data.encrypted_umk),
          nonce: encode_binary(umk_data.nonce),
          sender_device_id: umk_data.sender_device_id,
          sender_ecdh_public_key: encode_binary(sender.ecdh_public_key),
          sender_signing_public_key: encode_binary(sender.signing_public_key)
        })
    end
  end
end
