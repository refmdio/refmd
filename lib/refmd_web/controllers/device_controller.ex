defmodule RefMDWeb.DeviceController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Accounts
  alias RefMDWeb.Schemas

  operation(:create_pending,
    summary: "Create a pending device",
    request_body: {"Device params", "application/json", Schemas.CreatePendingDeviceRequest},
    responses: [
      created: {"Pending device", "application/json", Schemas.CreatePendingDeviceResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_pending(conn, params) do
    user_id = conn.assigns.current_user_id

    case Accounts.create_pending_device(%{
           user_id: user_id,
           name: params["name"],
           device_type: params["device_type"],
           ecdh_public_key: decode_binary!(params["ecdh_public_key"]),
           signing_public_key: decode_binary!(params["signing_public_key"]),
           client_nonce: decode_binary!(params["client_nonce"]),
           ip_address: to_string(:inet_parse.ntoa(conn.remote_ip))
         }) do
      {:ok, pending} ->
        conn
        |> put_status(:created)
        |> json(%{id: pending.id})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_device", details: format_errors(changeset)})
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

  def approve(conn, %{"id" => id} = params) do
    user_id = conn.assigns.current_user_id

    case Accounts.get_valid_pending_device(id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      %{user_id: ^user_id} = pending ->
        identity_signature = decode_binary!(params["identity_signature"])
        session = conn.assigns.current_session

        case Accounts.approve_pending_device(pending, identity_signature,
               is_recovery: session.is_recovery
             ) do
          {:ok, device} ->
            if session.device_id == nil do
              Accounts.bind_session_to_device(session.id, device.id)
            end

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

      _ ->
        conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  end

  defp decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  defp format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, _opts} -> msg end)
  end

  defp format_errors(_), do: %{}
end
