defmodule RefMDWeb.Channels.Document.Pop do
  @moduledoc false

  alias RefMD.Auth
  alias RefMD.Devices
  alias RefMD.Sharing

  @spec verify(map(), Ecto.UUID.t(), Phoenix.Socket.t()) ::
          {:ok, map()} | {:error, %{reason: String.t()}}
  def verify(params, user_id, socket) do
    if socket.assigns[:session_kind] == :share_participant do
      verify_share_pop(params, socket)
    else
      session = socket.assigns.current_session

      with {:ok, device_id} <- get_session_device_id(session),
           {:ok, challenge} <- decode_param(params, "pop_challenge"),
           {:ok, signature} <- decode_param(params, "pop_signature"),
           {:ok, device} <- get_active_device(user_id, device_id),
           :ok <- verify_pop_signature(challenge, signature, device),
           :ok <- Auth.consume_pop_challenge(challenge, user_id, device.id) do
        {:ok, device}
      else
        {:error, _reason} -> {:error, %{reason: "pop_verification_failed"}}
      end
    end
  end

  defp verify_share_pop(params, socket) do
    share_id = socket.assigns.current_share_id
    principal_id = socket.assigns.share_participant_principal_id
    session = socket.assigns.current_session

    with device_id when is_binary(device_id) <- session.device_id,
         {:ok, challenge} <- decode_param(params, "pop_challenge"),
         {:ok, signature} <- decode_param(params, "pop_signature"),
         {:ok, device} <- get_active_share_device(principal_id, device_id),
         :ok <- verify_pop_signature(challenge, signature, device),
         :ok <- Sharing.consume_pop_challenge(challenge, share_id, device.id) do
      {:ok, device}
    else
      _ -> {:error, %{reason: "pop_verification_failed"}}
    end
  end

  defp get_session_device_id(session) do
    case Auth.get_session(session.id) do
      %{device_id: nil} -> {:error, :unbound_session}
      %{device_id: id} -> {:ok, id}
      nil -> {:error, :session_expired}
    end
  end

  defp get_active_device(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp get_active_share_device(principal_id, device_id) do
    case Sharing.get_participant_device(device_id) do
      %{principal_id: ^principal_id} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_pop_signature(challenge, signature, device) do
    message =
      RefMD.Crypto.build_signature_message("pop_challenge", %{
        "challenge" => Base.url_encode64(challenge, padding: false),
        "device_id" => device.id
      })

    if RefMD.Crypto.verify_ed25519_signature(message, signature, device.signing_public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp decode_param(params, key) do
    case params[key] do
      nil -> {:error, :"missing_#{key}"}
      val -> Base.url_decode64(val, padding: false) |> wrap_decode_error(key)
    end
  end

  defp wrap_decode_error({:ok, _} = ok, _key), do: ok
  defp wrap_decode_error(:error, key), do: {:error, :"invalid_#{key}"}
end
