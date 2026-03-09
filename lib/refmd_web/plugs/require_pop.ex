defmodule RefMDWeb.Plugs.RequirePoP do
  @moduledoc """
  Plug that validates Proof-of-Possession (PoP) on every request.

  Requires authenticated session (RequireAuth must run first).
  Validates X-PoP-Challenge, X-PoP-Signature, X-PoP-Device-Id headers.
  On first PoP after device approval, auto-binds session to device.
  """

  import Plug.Conn
  alias RefMD.Accounts

  @touch_interval_seconds 5 * 60

  def init(opts), do: opts

  def call(conn, _opts) do
    with {:ok, device_id} <- get_pop_device_id(conn),
         {:ok, challenge} <- get_pop_challenge(conn),
         {:ok, signature} <- get_pop_signature(conn),
         user_id = conn.assigns.current_user_id,
         {:ok, device} <- verify_device_ownership(user_id, device_id),
         :ok <- verify_pop_signature(challenge, signature, device, user_id),
         :ok <- Accounts.consume_pop_challenge(challenge, user_id, device_id),
         {:ok, conn} <- maybe_bind_session(conn, device_id) do
      maybe_touch_device(device)

      conn
      |> assign(:pop_device_id, device_id)
      |> assign(:pop_device, device)
    else
      {:error, reason} ->
        conn
        |> put_status(:forbidden)
        |> Phoenix.Controller.json(%{error: pop_error_message(reason)})
        |> halt()
    end
  end

  defp get_pop_device_id(conn) do
    case get_req_header(conn, "x-pop-device-id") do
      [device_id | _] -> {:ok, device_id}
      [] -> {:error, :missing_device_id}
    end
  end

  defp get_pop_challenge(conn) do
    case get_req_header(conn, "x-pop-challenge") do
      [challenge_b64 | _] ->
        case Base.url_decode64(challenge_b64, padding: false) do
          {:ok, challenge} -> {:ok, challenge}
          :error -> {:error, :invalid_challenge_encoding}
        end

      [] ->
        {:error, :missing_challenge}
    end
  end

  defp get_pop_signature(conn) do
    case get_req_header(conn, "x-pop-signature") do
      [sig_b64 | _] ->
        case Base.url_decode64(sig_b64, padding: false) do
          {:ok, signature} -> {:ok, signature}
          :error -> {:error, :invalid_signature_encoding}
        end

      [] ->
        {:error, :missing_signature}
    end
  end

  defp verify_device_ownership(user_id, device_id) do
    case Accounts.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_pop_signature(challenge, signature, device, _user_id) do
    message = build_pop_message(challenge, device.id)

    if :crypto.verify(:eddsa, :none, message, signature, [device.signing_public_key, :ed25519]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp build_pop_message(challenge, device_id) do
    # JCS canonicalization: sorted keys, no whitespace
    challenge_b64 = Base.url_encode64(challenge, padding: false)

    fields = %{
      "action" => "pop_challenge",
      "challenge" => challenge_b64,
      "device_id" => device_id,
      "protocol" => "refmd",
      "version" => 1
    }

    pairs =
      fields
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {k, v} ->
        Jason.encode!(k) <> ":" <> encode_jcs_value(v)
      end)

    "{" <> Enum.join(pairs, ",") <> "}"
  end

  defp encode_jcs_value(v) when is_binary(v), do: Jason.encode!(v)
  defp encode_jcs_value(v) when is_integer(v), do: Integer.to_string(v)

  defp maybe_bind_session(conn, device_id) do
    session = conn.assigns.current_session

    cond do
      session.device_id == nil ->
        case Accounts.bind_session_to_device(session.id, device_id) do
          {1, _} ->
            {:ok,
             conn
             |> assign(:current_session, %{session | device_id: device_id, is_recovery: false})
             |> assign(:device_verified, true)}

          {0, _} ->
            # Race condition: another request already bound this session.
            # Re-read from DB to check if it was bound to the same device.
            case Accounts.get_session(session.id) do
              %{device_id: ^device_id} ->
                {:ok,
                 conn
                 |> assign(:current_session, %{session | device_id: device_id, is_recovery: false})
                 |> assign(:device_verified, true)}

              _ ->
                {:error, :device_session_mismatch}
            end
        end

      session.device_id == device_id ->
        {:ok, conn}

      true ->
        {:error, :device_session_mismatch}
    end
  end

  defp pop_error_message(:missing_device_id), do: "pop_missing_device_id"
  defp pop_error_message(:missing_challenge), do: "pop_missing_challenge"
  defp pop_error_message(:missing_signature), do: "pop_missing_signature"
  defp pop_error_message(:invalid_challenge_encoding), do: "pop_invalid_challenge"
  defp pop_error_message(:invalid_signature_encoding), do: "pop_invalid_signature"
  defp pop_error_message(:invalid_device), do: "pop_invalid_device"
  defp pop_error_message(:invalid_signature), do: "pop_invalid_signature"
  defp pop_error_message(:invalid_challenge), do: "pop_invalid_or_expired_challenge"
  defp pop_error_message(:device_session_mismatch), do: "pop_device_session_mismatch"
  defp pop_error_message(_), do: "pop_verification_failed"

  defp maybe_touch_device(device) do
    elapsed = DateTime.diff(DateTime.utc_now(), device.last_seen_at, :second)

    if elapsed >= @touch_interval_seconds do
      Accounts.touch_device(device.id)
    end
  end
end
