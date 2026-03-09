defmodule RefMDWeb.TrustTransferController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Accounts
  alias RefMDWeb.{Schemas, DeviceEventsController}

  operation(:create_nonce,
    summary: "Request a trust transfer nonce",
    request_body: {"Nonce request", "application/json", Schemas.TrustTransferNonceRequest},
    responses: [
      ok: {"Nonce response", "application/json", Schemas.TrustTransferNonceResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_nonce(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id
    session = conn.assigns.current_session

    cond do
      session.device_id != nil ->
        conn |> put_status(:forbidden) |> json(%{error: "bound_session"})

      not (Accounts.user_owns_active_device?(user_id, device_id) or
             Accounts.user_owns_pending_device?(user_id, device_id)) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
      case Accounts.create_trust_transfer_nonce(user_id, device_id) do
        {:ok, nonce, expires_at} ->
          DeviceEventsController.broadcast_trust_transfer_nonce_ready(user_id, device_id, nonce)

          json(conn, %{
            nonce: Base.url_encode64(nonce, padding: false),
            expires_at: DateTime.to_iso8601(expires_at)
          })

        {:error, _} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "nonce_creation_failed"})
      end
    end
  end

  operation(:send_state,
    summary: "Send encrypted trust state (existing device, PoP required)",
    request_body: {"Trust state", "application/json", Schemas.TrustTransferSendRequest},
    responses: [
      ok: {"State saved", "application/json", Schemas.OkResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse},
      request_entity_too_large: {"Payload too large", "application/json", Schemas.ErrorResponse}
    ]
  )

  def send_state(conn, params) do
    user_id = conn.assigns.current_user_id
    target_device_id = params["target_device_id"]

    target_valid =
      case Accounts.get_device(target_device_id) do
        %{user_id: ^user_id, revoked_at: nil} -> true
        _ ->
          case Accounts.get_valid_pending_device(target_device_id) do
            %{user_id: ^user_id} -> true
            _ -> false
          end
      end

    unless target_valid do
      conn |> put_status(:forbidden) |> json(%{error: "invalid_target_device"})
    else
      with {:ok, transfer_nonce} <- decode_binary(params["transfer_nonce"]),
           {:ok, ciphertext} <- decode_binary(params["ciphertext"]),
           {:ok, nonce} <- decode_binary(params["nonce"]),
           {:ok, signature} <- decode_binary(params["signature"]) do
        if byte_size(ciphertext) > Accounts.trust_transfer_max_payload_bytes() do
          conn |> put_status(:request_entity_too_large) |> json(%{error: "payload_too_large"})
        else
          with :ok <- Accounts.consume_trust_transfer_nonce(user_id, target_device_id, transfer_nonce) do
            case Accounts.save_trust_transfer_state(%{
                   user_id: user_id,
                   target_device_id: target_device_id,
                   sender_device_id: conn.assigns[:pop_device_id],
                   ciphertext: ciphertext,
                   nonce: nonce,
                   signature: signature
                 }) do
              {:ok, _} ->
                json(conn, %{ok: true})

              {:error, _} ->
                conn |> put_status(:unprocessable_entity) |> json(%{error: "save_failed"})
            end
          else
            {:error, :invalid_nonce} ->
              conn |> put_status(:forbidden) |> json(%{error: "invalid_or_expired_nonce"})
          end
        end
      else
        {:error, :invalid_base64} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
      end
    end
  end

  operation(:get_state,
    summary: "Retrieve and consume trust state for a device (new device, no PoP)",
    parameters: [
      device_id: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Trust state", "application/json", Schemas.TrustTransferGetResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Invalid device", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_state(conn, %{"device_id" => device_id}) do
    user_id = conn.assigns.current_user_id
    session = conn.assigns.current_session

    cond do
      session.device_id != nil ->
        conn |> put_status(:forbidden) |> json(%{error: "bound_session"})

      not (Accounts.user_owns_active_device?(user_id, device_id) or
             Accounts.user_owns_pending_device?(user_id, device_id)) ->
        conn |> put_status(:forbidden) |> json(%{error: "invalid_device"})

      true ->
      case Accounts.consume_trust_transfer_state(user_id, device_id) do
        {:ok, state} ->
          sender = Accounts.get_device(state.sender_device_id)

          json(conn, %{
            sender_device_id: state.sender_device_id,
            sender_ecdh_public_key: sender && encode_binary(sender.ecdh_public_key),
            sender_signing_public_key: sender && encode_binary(sender.signing_public_key),
            ciphertext: encode_binary(state.ciphertext),
            nonce: encode_binary(state.nonce),
            signature: encode_binary(state.signature)
          })

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "not_found"})
      end
    end
  end

  defp decode_binary(base64) when is_binary(base64) do
    case Base.url_decode64(base64, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_base64}
    end
  end

  defp decode_binary(_), do: {:error, :invalid_base64}

  defp encode_binary(nil), do: nil
  defp encode_binary(bin), do: Base.url_encode64(bin, padding: false)
end
