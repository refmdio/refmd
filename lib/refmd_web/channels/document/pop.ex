defmodule RefMDWeb.Channels.Document.Pop do
  @moduledoc false

  alias RefMD.Auth
  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Devices
  alias RefMD.Sharing
  alias RefMDWeb.Http.PopSessionBinding
  alias RefMDWeb.Http.PopTranscript

  @spec verify(map(), Ecto.UUID.t(), Phoenix.Socket.t(), Ecto.UUID.t(), Ecto.UUID.t() | nil) ::
          {:ok, map()} | {:error, %{reason: String.t()}}
  def verify(params, user_id, socket, document_id, mounted_share_id \\ nil) do
    if socket.assigns[:session_kind] == :share_participant do
      verify_share_pop(params, socket, document_id, mounted_share_id)
    else
      verify_user_pop(params, user_id, socket, document_id)
    end
  end

  defp verify_user_pop(params, user_id, socket, document_id) do
    session = socket.assigns.current_session

    with {:ok, device_id, verified_session} <- get_user_pop_device_id(params, session),
         {:ok, "user_device"} <- get_actor_variant(params),
         {:ok, {challenge, challenge_bytes}} <- decode_challenge(params),
         {:ok, signature} <- decode_signature(params),
         {:ok, device} <- get_active_device(user_id, device_id),
         :ok <-
           verify_user_pop_signature(
             challenge,
             signature,
             device,
             user_id,
             verified_session,
             document_id,
             params
           ),
         :ok <-
           Auth.consume_pop_challenge(challenge_bytes, user_id, device.id, verified_session.id) do
      {:ok, device}
    else
      {:error, :invalid_signature} ->
        {:error, %{reason: "pop_verification_failed"}}

      {:error, reason} ->
        {:error, %{reason: pop_semantic_error(reason)}}
    end
  end

  defp verify_share_pop(params, socket, document_id, _mounted_share_id) do
    share_id = socket.assigns.current_share_id
    principal_id = socket.assigns.share_participant_principal_id
    session = socket.assigns.current_session

    with {:ok, device_id} <- get_share_pop_device_id(params, session),
         {:ok, "share_participant_device"} <- get_actor_variant(params),
         {:ok, {challenge, challenge_bytes}} <- decode_challenge(params),
         {:ok, signature} <- decode_signature(params),
         {:ok, device} <- get_active_share_device(share_id, principal_id, device_id),
         :ok <-
           verify_share_pop_signature(
             challenge,
             signature,
             device,
             principal_id,
             session,
             document_id,
             share_id,
             params
           ),
         :ok <-
           Sharing.consume_pop_challenge(
             challenge_bytes,
             share_id,
             principal_id,
             device.id,
             session.id
           ) do
      {:ok, device}
    else
      {:error, :invalid_signature} ->
        {:error, %{reason: "pop_verification_failed"}}

      {:error, reason} ->
        {:error, %{reason: pop_semantic_error(reason)}}

      _ ->
        {:error, %{reason: "pop_verification_failed"}}
    end
  end

  defp get_user_pop_device_id(params, session) do
    with {:ok, current_session} <- get_current_session(session),
         {:ok, param_device_id} <- get_param_device_id(params) do
      case current_session.device_id do
        ^param_device_id -> {:ok, param_device_id, current_session}
        _ -> {:error, :device_session_mismatch}
      end
    else
      _ -> {:error, :device_session_mismatch}
    end
  end

  defp get_share_pop_device_id(params, session) do
    with device_id when is_binary(device_id) <- session.device_id,
         {:ok, param_device_id} <- get_param_device_id(params),
         true <- param_device_id == device_id do
      {:ok, device_id}
    else
      _ -> {:error, :device_session_mismatch}
    end
  end

  defp get_current_session(session) do
    case Auth.get_session(session.id) do
      %{id: _} = current_session -> {:ok, current_session}
      nil -> {:error, :session_expired}
    end
  end

  defp get_param_device_id(params) do
    case params["pop_device_id"] do
      device_id when is_binary(device_id) -> {:ok, device_id}
      _ -> {:error, :missing_pop_device_id}
    end
  end

  defp get_actor_variant(params) do
    case params["pop_actor_variant"] do
      "user_device" -> {:ok, "user_device"}
      "share_participant_device" -> {:ok, "share_participant_device"}
      _ -> {:error, :invalid_pop_actor_variant}
    end
  end

  defp get_active_device(user_id, device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp get_active_share_device(share_id, principal_id, device_id) do
    case Sharing.get_participant_device(share_id, principal_id, device_id) do
      %{principal_id: ^principal_id} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_user_pop_signature(
         challenge,
         signature,
         device,
         user_id,
         session,
         document_id,
         params
       ) do
    transcript =
      Signature.build_pop_transcript!(
        "channel_user_device",
        "device",
        device.id,
        PopTranscript.user_actor!(device, user_id),
        challenge,
        PopSessionBinding.for_user_session(session),
        channel_resource(document_id, "user", nil, params)
      )

    case Signature.verify_hybrid_signature_result(
           "pop_request",
           transcript,
           signature,
           device.hybrid_signing_public_key_material,
           %{
             challenge: challenge,
             device: device,
             session: PopSessionBinding.for_user_session(session),
             user_id: user_id
           }
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp verify_share_pop_signature(
         challenge,
         signature,
         device,
         _principal_id,
         session,
         document_id,
         share_id,
         params
       ) do
    workspace_id = Sharing.share_workspace_id!(share_id)

    transcript =
      Signature.build_pop_transcript!(
        "channel_share_participant_device",
        "share_participant_device",
        device.id,
        PopTranscript.share_participant_actor!(device, share_id, workspace_id),
        challenge,
        PopSessionBinding.for_share_session(session),
        channel_resource(document_id, "share", share_id, params)
      )

    case Signature.verify_hybrid_signature_result(
           "pop_request",
           transcript,
           signature,
           device.hybrid_signing_public_key_material,
           %{
             challenge: challenge,
             device: device,
             principal_id: device.principal_id,
             session: PopSessionBinding.for_share_session(session),
             share_id: share_id
           }
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp pop_semantic_error(reason) when is_atom(reason), do: "pop_" <> Atom.to_string(reason)

  defp channel_resource(document_id, scope_kind, share_id, params) do
    share_id = if scope_kind == "share", do: share_id, else: "none"

    %{
      "channel_event" => "phx_join",
      "document_id" => document_id,
      "event_name" => "phx_join",
      "join_push_kind" => "join",
      "payload_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(join_payload(params))),
      "scope_kind" => scope_kind,
      "share_id" => share_id || "",
      "topic" => "document:#{document_id}"
    }
  end

  defp join_payload(params) when is_map(params) do
    Map.drop(params, [
      "pop_actor_variant",
      "pop_challenge",
      "pop_device_id",
      "pop_signature",
      "pop_signature_transport"
    ])
  end

  defp decode_challenge(params) do
    case params["pop_challenge"] do
      nil -> {:error, :missing_pop_challenge}
      value -> {:ok, {value, Encoding.decode_base64url!(value)}}
    end
  rescue
    ArgumentError -> {:error, :invalid_pop_challenge}
  end

  defp decode_signature(params) do
    if Map.has_key?(params, "pop_signature_transport") do
      {:error, :invalid_pop_signature}
    else
      decode_signature_object(params["pop_signature"])
    end
  end

  defp decode_signature_object(signature) do
    case signature do
      nil ->
        {:error, :missing_pop_signature}

      value when is_map(value) ->
        JCS.canonical_bytes!(value)
        {:ok, value}

      _value ->
        {:error, :invalid_pop_signature}
    end
  rescue
    ArgumentError -> {:error, :invalid_pop_signature}
  end
end
