defmodule RefMDWeb.Plugs.RequireRrp do
  @moduledoc """
  Plug that validates RefMD Request Proof (RRP) on every request.

  Requires authenticated session (RequireAuth must run first).
  Validates X-RefMD-RRP-Challenge, X-RefMD-RRP-Signature-Transport,
  X-RefMD-RRP-Actor-Variant, and X-RefMD-RRP-Device-Id headers.
  On first RRP after device approval, auto-binds session to device.
  """

  import Plug.Conn
  alias RefMD.Auth
  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Devices
  alias RefMD.Sharing
  alias RefMDWeb.Http.RrpSessionBinding
  alias RefMDWeb.Http.RrpTranscript

  @touch_interval_seconds 5 * 60

  def init(opts), do: opts

  def call(conn, opts) do
    with {:ok, device_id} <- get_rrp_device_id(conn),
         {:ok, actor_variant} <- get_actor_variant(conn, opts),
         {:ok, {challenge, challenge_bytes}} <- get_rrp_challenge(conn),
         {:ok, signature} <- get_rrp_signature(conn),
         {:ok, conn} <-
           verify_actor_rrp(conn, actor_variant, device_id, challenge, challenge_bytes, signature) do
      conn
    else
      {:error, reason} ->
        conn
        |> put_status(:forbidden)
        |> Phoenix.Controller.json(%{error: rrp_error_message(reason)})
        |> halt()
    end
  end

  defp get_rrp_device_id(conn) do
    case get_req_header(conn, "x-refmd-rrp-device-id") do
      [device_id | _] -> {:ok, device_id}
      [] -> {:error, :missing_device_id}
    end
  end

  defp get_rrp_challenge(conn) do
    case get_req_header(conn, "x-refmd-rrp-challenge") do
      [challenge_b64 | _] ->
        {:ok, {challenge_b64, Encoding.decode_base64url!(challenge_b64)}}

      [] ->
        {:error, :missing_challenge}
    end
  rescue
    ArgumentError -> {:error, :invalid_challenge_encoding}
  end

  defp get_actor_variant(conn, opts) do
    case get_req_header(conn, "x-refmd-rrp-actor-variant") do
      ["user_device" | _] ->
        {:ok, "user_device"}

      ["share_participant_device" | _] ->
        if Keyword.get(opts, :allow_share_participant, false),
          do: {:ok, "share_participant_device"},
          else: {:error, :invalid_actor_variant}

      [_ | _] ->
        {:error, :invalid_actor_variant}

      [] ->
        {:error, :missing_actor_variant}
    end
  end

  defp get_rrp_signature(conn) do
    cond do
      get_req_header(conn, "x-refmd-rrp-signature") != [] ->
        {:error, :invalid_signature_encoding}

      body_rrp_signature?(conn) ->
        {:error, :invalid_signature_encoding}

      true ->
        get_rrp_signature_transport(conn)
    end
  end

  defp body_rrp_signature?(%{body_params: params}) do
    Map.has_key?(params, "rrp_signature") or Map.has_key?(params, "rrp_signature_transport")
  end

  defp get_rrp_signature_transport(conn) do
    case get_req_header(conn, "x-refmd-rrp-signature-transport") do
      [sig_b64 | _] ->
        signature_bytes = Encoding.decode_base64url!(sig_b64)
        signature = JCS.parse_json_strict!(signature_bytes)

        if JCS.canonical_bytes!(signature) == signature_bytes,
          do: {:ok, signature},
          else: {:error, :invalid_signature_encoding}

      [] ->
        {:error, :missing_signature}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature_encoding}
  end

  defp verify_device_ownership(user_id, device_id) do
    if Devices.user_owns_active_device?(user_id, device_id),
      do: {:ok, Devices.get_device(device_id)},
      else: {:error, :invalid_device}
  end

  defp verify_rrp_signature(conn, challenge, signature, device, user_id) do
    transcript =
      Signature.build_rrp_transcript!(
        "http_user_device",
        "device",
        device.id,
        RrpTranscript.user_actor!(device, user_id),
        challenge,
        RrpSessionBinding.for_user_session(conn.assigns.current_session),
        rrp_resource(conn)
      )

    case Signature.verify_hybrid_signature_result(
           "rrp_request",
           transcript,
           signature,
           device.hybrid_signing_public_key_material,
           %{
             challenge: challenge,
             device: device,
             session: RrpSessionBinding.for_user_session(conn.assigns.current_session),
             user_id: user_id
           }
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp verify_actor_rrp(conn, "user_device", device_id, challenge, challenge_bytes, signature) do
    user_id = conn.assigns.current_user_id

    with {:ok, device} <- verify_device_ownership(user_id, device_id),
         :ok <- verify_rrp_signature(conn, challenge, signature, device, user_id),
         :ok <-
           Auth.consume_rrp_challenge(
             challenge_bytes,
             user_id,
             device_id,
             conn.assigns.current_session.id
           ),
         {:ok, conn} <- maybe_bind_session(conn, device_id) do
      maybe_touch_device(device)

      {:ok,
       conn
       |> assign(:rrp_device_id, device_id)
       |> assign(:rrp_device, device)}
    end
  end

  defp verify_actor_rrp(
         conn,
         "share_participant_device",
         device_id,
         challenge,
         challenge_bytes,
         signature
       ) do
    principal_id = conn.assigns[:share_participant_principal_id]
    share_id = conn.assigns[:current_share_id]
    session_device_id = conn.assigns.current_session.device_id

    with :ok <- verify_share_session_device(session_device_id, device_id),
         {:ok, device} <- verify_share_participant_device(share_id, principal_id, device_id),
         :ok <- verify_share_rrp_signature(conn, challenge, signature, device, share_id),
         :ok <-
           Sharing.consume_rrp_challenge(
             challenge_bytes,
             share_id,
             principal_id,
             device_id,
             conn.assigns.current_session.id
           ) do
      {:ok,
       conn
       |> assign(:rrp_device_id, device_id)
       |> assign(:rrp_device, device)}
    end
  end

  defp verify_share_participant_device(share_id, principal_id, device_id)
       when is_binary(share_id) and is_binary(principal_id) and is_binary(device_id) do
    case Sharing.get_participant_device(share_id, principal_id, device_id) do
      %{principal_id: ^principal_id} = device -> {:ok, device}
      _ -> {:error, :invalid_device}
    end
  end

  defp verify_share_participant_device(_, _, _), do: {:error, :invalid_device}

  defp verify_share_session_device(device_id, device_id) when is_binary(device_id), do: :ok
  defp verify_share_session_device(_, _), do: {:error, :device_session_mismatch}

  defp verify_share_rrp_signature(conn, challenge, signature, device, share_id) do
    workspace_id = Sharing.share_workspace_id!(share_id)

    transcript =
      Signature.build_rrp_transcript!(
        "http_share_participant_device",
        "share_participant_device",
        device.id,
        RrpTranscript.share_participant_actor!(device, share_id, workspace_id),
        challenge,
        RrpSessionBinding.for_share_session(conn.assigns.current_session),
        rrp_resource(conn)
      )

    case Signature.verify_hybrid_signature_result(
           "rrp_request",
           transcript,
           signature,
           device.hybrid_signing_public_key_material,
           %{
             challenge: challenge,
             device: device,
             principal_id: conn.assigns[:share_participant_principal_id],
             session: RrpSessionBinding.for_share_session(conn.assigns.current_session),
             share_id: share_id
           }
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp rrp_resource(conn) do
    canonical_query = canonical_query_string!(conn.query_string)

    %{
      "body_hash" => rrp_body_hash(conn),
      "canonical_query" => canonical_query,
      "method" => conn.method,
      "path" => conn.request_path,
      "query_hash" => Hash.blake3_base64url(canonical_query)
    }
  end

  defp canonical_query_string!(""), do: ""

  defp canonical_query_string!(query) when is_binary(query) do
    query
    |> String.split("&")
    |> Enum.map(&decode_query_pair!/1)
    |> Enum.sort()
    |> Enum.map_join("&", fn {key, value} ->
      percent_encode_query_component(key) <> "=" <> percent_encode_query_component(value)
    end)
  end

  defp decode_query_pair!(pair) do
    case String.split(pair, "=", parts: 2) do
      [key, value] -> {decode_query_component!(key), decode_query_component!(value)}
      [key] -> {decode_query_component!(key), ""}
    end
  end

  defp decode_query_component!(value) do
    value
    |> String.replace("+", " ")
    |> URI.decode()
  end

  defp percent_encode_query_component(value),
    do: URI.encode(value, &query_unreserved?/1)

  defp query_unreserved?(char)
       when char in ?A..?Z or char in ?a..?z or char in ?0..?9 or char in [?-, ?., ?_, ?~],
       do: true

  defp query_unreserved?(_char), do: false

  defp rrp_body_hash(conn) do
    (conn.private[:raw_body] || "")
    |> IO.iodata_to_binary()
    |> Hash.blake3_base64url()
  end

  defp maybe_bind_session(conn, device_id) do
    session = conn.assigns.current_session

    cond do
      session.device_id == nil ->
        bind_unbound_session(conn, session, device_id)

      session.device_id == device_id ->
        {:ok, conn}

      true ->
        {:error, :device_session_mismatch}
    end
  end

  defp bind_unbound_session(conn, session, device_id) do
    case Auth.bind_session_to_device(session.id, device_id) do
      {1, _} ->
        {:ok, assign_bound_session(conn, session, device_id)}

      {0, _} ->
        handle_bind_race_condition(conn, session, device_id)
    end
  end

  defp handle_bind_race_condition(conn, session, device_id) do
    case Auth.get_session(session.id) do
      %{device_id: ^device_id} ->
        {:ok, assign_bound_session(conn, session, device_id)}

      _ ->
        {:error, :device_session_mismatch}
    end
  end

  defp assign_bound_session(conn, session, device_id) do
    conn
    |> assign(:current_session, %{session | device_id: device_id, is_recovery: false})
    |> assign(:device_verified, true)
  end

  defp rrp_error_message(:missing_device_id), do: "rrp_missing_device_id"
  defp rrp_error_message(:missing_challenge), do: "rrp_missing_challenge"
  defp rrp_error_message(:missing_actor_variant), do: "rrp_missing_actor_variant"
  defp rrp_error_message(:invalid_actor_variant), do: "rrp_invalid_actor_variant"
  defp rrp_error_message(:missing_signature), do: "rrp_missing_signature"
  defp rrp_error_message(:invalid_challenge_encoding), do: "rrp_invalid_challenge"
  defp rrp_error_message(:invalid_signature_encoding), do: "rrp_invalid_signature"
  defp rrp_error_message(:invalid_device), do: "rrp_invalid_device"
  defp rrp_error_message(:invalid_signature), do: "rrp_invalid_signature"
  defp rrp_error_message(:invalid_challenge), do: "rrp_invalid_or_expired_challenge"
  defp rrp_error_message(:device_session_mismatch), do: "rrp_device_session_mismatch"
  defp rrp_error_message(reason) when is_atom(reason), do: "rrp_" <> Atom.to_string(reason)

  defp maybe_touch_device(device) do
    elapsed = DateTime.diff(DateTime.utc_now(), device.last_seen_at, :second)

    if elapsed >= @touch_interval_seconds do
      Devices.touch_device(device.id)
    end
  end
end
