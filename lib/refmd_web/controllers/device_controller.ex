defmodule RefMDWeb.DeviceController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Auth, Devices}
  alias RefMD.Auth.Genesis.Commit, as: GenesisCommit
  alias RefMD.Auth.Genesis.Intent, as: GenesisIntent
  alias RefMD.Crypto.{Encoding, Hash}
  alias RefMD.Security

  alias RefMDWeb.Http.SessionCookies
  alias RefMDWeb.Payloads.DeviceIdentity
  alias RefMDWeb.Payloads.DeviceRegistration, as: RegistrationPayload
  alias RefMDWeb.Schemas

  operation(:bootstrap_challenge,
    summary: "Issue first-device bootstrap registration challenge",
    responses: [
      ok:
        {"Registration challenge", "application/json",
         Schemas.BootstrapRegistrationChallengeResponse},
      conflict: {"Already has devices", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def bootstrap_challenge(conn, _params) do
    genesis = conn.assigns.pending_account_genesis
    session = conn.assigns.pending_genesis_session

    case Auth.Genesis.issue_challenge(genesis, session) do
      {:ok, challenge} ->
        json(conn, %{
          registration_challenge: Base.url_encode64(challenge.challenge, padding: false),
          expires_in_seconds:
            max(DateTime.diff(challenge.expires_at, DateTime.utc_now(), :second), 1)
        })

      {:error, :invalid_genesis_session} ->
        conn |> put_status(:unauthorized) |> json(%{error: "invalid_genesis_session"})
    end
  end

  operation(:bootstrap_intent,
    summary: "Prepare the account genesis compound append intent",
    request_body: {
      "Account genesis prepare request",
      "application/json",
      Schemas.AccountGenesisPrepareRequest
    },
    responses: [
      ok: {"Compound append intent", "application/json", %OpenApiSpex.Schema{type: :object}},
      conflict: {"Genesis state conflict", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def bootstrap_intent(conn, params) do
    case GenesisIntent.issue!(
           conn.assigns.pending_account_genesis,
           conn.assigns.pending_genesis_session,
           params
         ) do
      {:ok, intent} ->
        json(conn, intent)

      {:error, reason}
      when reason in [
             :invalid_genesis_challenge,
             :genesis_intent_reuse,
             :invalid_genesis_session
           ] ->
        conn |> put_status(:conflict) |> json(%{error: Atom.to_string(reason)})

      {:error, reason} when is_binary(reason) ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: reason})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_genesis_intent", details: format_errors(changeset)})

      {:error, _reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_genesis_intent"})
    end
  end

  operation(:registration_challenge,
    summary: "Issue pending device registration challenge",
    responses: [
      ok: {"Registration challenge", "application/json", Schemas.RegistrationChallengeResponse}
    ]
  )

  def registration_challenge(conn, _params) do
    user_id = conn.assigns.current_user_id
    session = conn.assigns.current_session

    case Devices.issue_registration_challenge(user_id, session) do
      {:ok, challenge} ->
        json(conn, registration_challenge_response(challenge))

      {:error, :session_not_found} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "session_not_found"})

      {:error, :server_clock_regression} ->
        conn |> put_status(:service_unavailable) |> json(%{error: "server_clock_regression"})
    end
  end

  operation(:bootstrap,
    summary: "Commit the account genesis compound authorization",
    request_body: {"Bootstrap params", "application/json", Schemas.BootstrapDeviceRequest},
    responses: [
      created: {"Bootstrapped device", "application/json", Schemas.BootstrapDeviceResponse},
      conflict: {"Genesis state conflict", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse},
      service_unavailable:
        {"Security audit unavailable", "application/json", Schemas.ErrorResponse}
    ]
  )

  def bootstrap(conn, params) do
    case GenesisCommit.commit(
           conn.assigns.pending_account_genesis,
           conn.assigns.pending_genesis_session,
           params
         ) do
      {:ok, %{response: response, session_token: token}} ->
        conn
        |> maybe_set_genesis_session(token)
        |> SessionCookies.delete_genesis_session_cookie()
        |> put_status(:created)
        |> json(response)

      {:error, reason}
      when reason in [:invalid_genesis_session, :audit_checkpoint_intent_reuse] ->
        conn |> put_status(:conflict) |> json(%{error: Atom.to_string(reason)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_genesis_commit", details: format_errors(changeset)})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: to_string(reason)})
    end
  end

  defp maybe_set_genesis_session(conn, token) when is_binary(token),
    do: SessionCookies.set_session_cookie(conn, token, false)

  defp maybe_set_genesis_session(conn, nil), do: conn

  operation(:create_registration,
    summary: "Create a device registration (2nd+ devices only)",
    request_body: {"Device params", "application/json", Schemas.CreateDeviceRegistrationRequest},
    responses: [
      created:
        {"Device registration", "application/json", Schemas.CreateDeviceRegistrationResponse},
      forbidden: {"Re-authentication required", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  # Re-authentication threshold for sensitive operations (5 minutes)
  @reauth_max_age_seconds 300

  def create_registration(conn, params) do
    session = conn.assigns.current_session

    if requires_reauth?(session) do
      conn |> put_status(:forbidden) |> json(%{error: "reauth_required"})
    else
      create_pending_after_reauth(conn, params)
    end
  end

  defp create_pending_after_reauth(conn, params) do
    user_id = conn.assigns.current_user_id
    session = conn.assigns.current_session

    with material <- RegistrationPayload.decode_request_material!(params),
         :ok <- Devices.validate_device_registration(user_id, material) do
      if session.is_recovery or Devices.user_has_any_device_records?(user_id) do
        create_device_registration(conn, params, user_id, material)
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

  defp create_device_registration(conn, params, user_id, material) do
    ua = get_req_header(conn, "user-agent") |> List.first() || ""
    session = conn.assigns.current_session
    pending_registration_challenge_hash = registration_challenge_hash!(params)

    with :ok <- validate_pending_registration_prekey(params, session),
         attrs <-
           device_registration_attrs(
             conn,
             params,
             user_id,
             material,
             pending_registration_challenge_hash,
             ua
           ),
         {:ok, %{removed_ids: removed_ids, pending: device_registration}} <-
           Devices.replace_user_device_registration(user_id, session.id, attrs) do
      for removed_id <- removed_ids do
        Security.record_device_registration_removed(user_id, removed_id)
      end

      Security.record_device_registration_created(user_id, device_registration)

      conn
      |> put_status(:created)
      |> json(%{status: "pending"})
    else
      {:error, :initial_ake_responder_prekey_required} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "initial_ake_responder_prekey_required"})

      {:error, _step, changeset, _} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_device", details: format_errors(changeset)})
    end
  end

  defp validate_pending_registration_prekey(params, session) do
    prekeys = params["ake_responder_prekeys"]

    if RegistrationPayload.valid_ake_responder_prekeys?(prekeys) and
         responder_prekey_freshness_matches_session?(prekeys, session) do
      :ok
    else
      {:error, :initial_ake_responder_prekey_required}
    end
  end

  defp responder_prekey_freshness_matches_session?(prekeys, session) do
    issued_at_ms = session.pending_registration_prekey_issued_at_ms
    expires_at_ms = session.pending_registration_prekey_expires_at_ms

    is_integer(issued_at_ms) and is_integer(expires_at_ms) and
      expires_at_ms == issued_at_ms + 300_000 and
      prekeys
      |> RegistrationPayload.normalize_ake_responder_prekeys()
      |> Map.values()
      |> Enum.all?(fn %{"payload" => payload} ->
        payload["issued_at_ms"] == issued_at_ms and payload["expires_at_ms"] == expires_at_ms
      end)
  end

  defp device_registration_attrs(
         conn,
         params,
         user_id,
         material,
         pending_registration_challenge_hash,
         ua
       ) do
    %{
      user_id: user_id,
      id: material.device_id,
      name: params["name"] || device_name_from_ua(ua),
      device_type: params["device_type"] || device_type_from_ua(ua),
      hybrid_encryption_public_key_material: material.hybrid_encryption_public_key_material,
      hybrid_signing_public_key_material: material.hybrid_signing_public_key_material,
      client_nonce: material.client_nonce,
      pending_registration_challenge_hash: pending_registration_challenge_hash,
      ake_responder_prekeys:
        RegistrationPayload.normalize_ake_responder_prekeys(params["ake_responder_prekeys"]),
      ip_address: to_string(:inet_parse.ntoa(conn.remote_ip))
    }
  end

  defp registration_challenge_response(%{
         challenge: challenge,
         expires_in_seconds: expires_in_seconds,
         issued_at_ms: issued_at_ms,
         expires_at_ms: expires_at_ms
       }) do
    %{
      registration_challenge: Base.url_encode64(challenge, padding: false),
      expires_in_seconds: expires_in_seconds,
      issued_at_ms: issued_at_ms,
      expires_at_ms: expires_at_ms
    }
  end

  defp registration_challenge_hash!(params) do
    case Map.fetch(params, "registration_challenge") do
      {:ok, challenge} ->
        challenge
        |> Encoding.decode_base64url!(32)
        |> Hash.blake3_base64url()

      :error ->
        raise ArgumentError, "registration_challenge_required"
    end
  end

  operation(:list_registrations,
    summary: "List device registrations for current user",
    responses: [
      ok: {"Device registrations", "application/json", Schemas.DeviceRegistrationsResponse}
    ]
  )

  def list_registrations(conn, _params) do
    user_id = conn.assigns.current_user_id
    device_registrations = Devices.get_user_device_registrations(user_id)

    json(conn, %{
      devices:
        Enum.map(device_registrations, fn pd ->
          %{
            id: pd.id,
            name: pd.name,
            device_type: pd.device_type,
            hybrid_encryption_public_key_material: pd.hybrid_encryption_public_key_material,
            encryption_key_id: pd.encryption_key_id,
            hybrid_signing_public_key_material: pd.hybrid_signing_public_key_material,
            signing_key_id: pd.signing_key_id,
            client_nonce: encode_binary(pd.client_nonce),
            pending_registration_challenge_hash: pd.pending_registration_challenge_hash,
            ake_responder_prekeys:
              RegistrationPayload.denormalize_ake_responder_prekeys(pd.ake_responder_prekeys),
            ip_address: pd.ip_address,
            created_at: pd.created_at,
            expires_at: pd.expires_at
          }
        end)
    })
  end

  operation(:reject_registration,
    summary: "Reject (delete) a device registration",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Rejection result", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def reject_registration(conn, %{"device_id" => id}) do
    user_id = conn.assigns.current_user_id

    case Devices.get_valid_device_registration(id) do
      %{user_id: ^user_id} ->
        Devices.delete_device_registration(id)
        Security.record_device_registration_removed(user_id, id)
        Security.record_registration_rejected(user_id, id)
        json(conn, %{ok: true})

      _ ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:get_registration_sas,
    summary: "Get device registration status (polling fallback for realtime events)",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Status", "application/json", Schemas.DeviceRegistrationStatusResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_registration_sas(conn, %{"device_id" => id}) do
    user_id = conn.assigns.current_user_id

    case Devices.get_device_registration_status(user_id, id) do
      {:ok, status} -> json(conn, %{status: status})
      {:error, :not_found} -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:approve,
    summary: "Approve a pending device",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Approval params", "application/json", Schemas.ApproveDeviceRequest, required: true},
    responses: [
      ok: {"Approved device", "application/json", Schemas.ApproveDeviceResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Approval failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def approve(conn, %{"device_id" => id} = params) do
    user_id = conn.assigns.current_user_id

    case Devices.get_valid_device_registration(id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      %{user_id: ^user_id} = device_registration ->
        approve_owned_device_registration(conn, device_registration, id, params)

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

  def list(conn, _params) do
    user_id = conn.assigns.current_user_id
    devices = Devices.get_user_devices(user_id)

    json(conn, %{
      devices:
        Enum.map(devices, fn d ->
          %{
            id: d.id,
            name: d.name,
            device_type: d.device_type,
            hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
            encryption_key_id: d.encryption_key_id,
            hybrid_signing_public_key_material: d.hybrid_signing_public_key_material,
            signing_key_id: d.signing_key_id,
            client_nonce: encode_binary(d.client_nonce),
            approval_signature: d.approval_signature,
            approval_signature_surface: d.approval_signature_surface,
            approval_proof: d.approval_proof,
            approval_delivery_commitments: d.approval_delivery_commitments,
            approval_delivery_artifacts:
              RegistrationPayload.denormalize_approval_delivery_artifacts(
                d.approval_delivery_artifacts
              ),
            key_checkpoint_sequence: d.key_checkpoint_sequence,
            key_checkpoint_hash: d.key_checkpoint_hash,
            last_seen_at: d.last_seen_at,
            created_at: d.created_at
          }
        end)
    })
  end

  operation(:revocation_intent,
    summary: "Prepare a device revocation compound append intent",
    parameters: [
      device_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Device revocation command", "application/json", Schemas.DeviceRevocationCommand,
       required: true},
    responses: [
      ok: {"Compound append intent", "application/json", %OpenApiSpex.Schema{type: :object}},
      bad_request: {"Bad request", "application/json", Schemas.ErrorResponse},
      conflict: {"Retire blocked", "application/json", Schemas.ErrorResponse}
    ]
  )

  def revocation_intent(conn, %{"device_id" => device_id} = command) do
    user_id = conn.assigns.current_user_id
    actor_device_id = conn.assigns.rrp_device_id

    case Devices.prepare_device_revocation(user_id, actor_device_id, device_id, command) do
      {:ok, intent} ->
        json(conn, intent)

      {:error, "retire_blocked_by_unbound_sessions"} ->
        conn |> put_status(:conflict) |> json(%{error: "retire_blocked_by_unbound_sessions"})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
    end
  end

  operation(:revoke,
    summary: "Commit an exact device revocation compound authorization",
    parameters: [device_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Device revocation authorization", "application/json",
       Schemas.DeviceRevocationAuthorization, required: true},
    responses: [
      ok: {"Revocation result", "application/json", Schemas.RevokeDeviceResponse},
      unprocessable_entity: {"Revocation failed", "application/json", Schemas.ErrorResponse}
    ]
  )

  def revoke(conn, %{"device_id" => device_id} = authorization) do
    case Devices.commit_device_revocation(
           conn.assigns.current_user_id,
           conn.assigns.rrp_device_id,
           device_id,
           Map.delete(authorization, "device_id")
         ) do
      {:ok, result} ->
        conn |> put_status(result.status) |> json(result.response)

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: inspect(reason)})
    end
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

  def rename(conn, %{"device_id" => device_id} = params) do
    user_id = conn.assigns.current_user_id
    name = params["name"]

    case Devices.rename_device(user_id, device_id, name) do
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

  operation(:initial_ake_offers,
    summary: "Get pending Initial AKE offers for the registering device",
    parameters: [device_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Initial AKE offers", "application/json", Schemas.InitialAkeExchangeResponse},
      forbidden: {"Invalid pending registration", "application/json", Schemas.ErrorResponse},
      not_found: {"Exchange not ready", "application/json", Schemas.ErrorResponse}
    ]
  )

  def initial_ake_offers(conn, %{"device_id" => device_id}) do
    session = conn.assigns.current_session

    if session.device_registration_id == device_id do
      case Devices.get_initial_ake_exchange(conn.assigns.current_user_id, device_id) do
        {:ok, %{offers: offers}} when is_map(offers) ->
          respond_with_initial_ake_offers(conn, offers)

        _ ->
          conn |> put_status(:not_found) |> json(%{error: "initial_ake_exchange_not_ready"})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "device_registration_mismatch"})
    end
  end

  defp respond_with_initial_ake_offers(conn, offers) do
    sender_device_id =
      get_in(offers, ["umk_distribution", "transcript", "initiator", "device_id"])

    case Devices.get_device(sender_device_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "initial_ake_sender_not_found"})

      sender ->
        json(
          conn,
          %{offers: offers, sender_device_id: sender.id}
          |> Map.merge(DeviceIdentity.sender_fields(sender))
        )
    end
  end

  operation(:initial_ake_responses,
    summary: "Submit one-time Initial AKE responder confirmations",
    parameters: [device_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Initial AKE responses", "application/json", Schemas.InitialAkeResponsesRequest},
    responses: [
      created: {"Responses accepted", "application/json", Schemas.OkResponse},
      conflict: {"Responses already consumed", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Invalid responses", "application/json", Schemas.ErrorResponse}
    ]
  )

  def initial_ake_responses(conn, %{"device_id" => device_id, "responses" => responses}) do
    session = conn.assigns.current_session

    if session.device_registration_id == device_id do
      case Devices.submit_initial_ake_responses(
             conn.assigns.current_user_id,
             device_id,
             responses
           ) do
        {:ok, _} ->
          conn |> put_status(:created) |> json(%{ok: true})

        {:error, :initial_ake_response_reused} ->
          conn |> put_status(:conflict) |> json(%{error: "initial_ake_response_reused"})

        {:error, reason} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: Atom.to_string(reason)})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "device_registration_mismatch"})
    end
  end

  def initial_ake_responses(conn, _params),
    do:
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_initial_ake_response"})

  operation(:initial_ake_response_status,
    summary: "Get Initial AKE responder confirmations for finalization",
    parameters: [device_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Initial AKE responses", "application/json", Schemas.InitialAkeResponsesResponse},
      forbidden: {"Invalid initiator", "application/json", Schemas.ErrorResponse},
      not_found: {"Responses not ready", "application/json", Schemas.ErrorResponse}
    ]
  )

  def initial_ake_response_status(conn, %{"device_id" => device_id}) do
    with {:ok, %{offers: offers, responses: responses}} when is_map(responses) <-
           Devices.get_initial_ake_exchange(conn.assigns.current_user_id, device_id),
         true <-
           get_in(offers, ["umk_distribution", "transcript", "initiator", "device_id"]) ==
             conn.assigns.rrp_device_id do
      json(conn, %{responses: responses})
    else
      false -> conn |> put_status(:forbidden) |> json(%{error: "initial_ake_initiator_mismatch"})
      _ -> conn |> put_status(:not_found) |> json(%{error: "initial_ake_responses_not_ready"})
    end
  end

  defp device_validation_error_response(error) do
    case error do
      :security_audit_unavailable -> {:service_unavailable, "security_audit_unavailable"}
      _ -> {:unprocessable_entity, Atom.to_string(error)}
    end
  end

  defp approve_owned_device_registration(conn, device_registration, id, params) do
    session = conn.assigns.current_session

    case approve_request_error(session, id, params) do
      :recovery_self_approval_only ->
        conn |> put_status(:forbidden) |> json(%{error: "recovery_self_approval_only"})

      :invalid_recovery_approval ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_recovery_approval"})

      :invalid_approval_surface ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_approval_surface"})

      :invalid_approval_proof ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_approval_proof"})

      :ok ->
        approve_owned_device_registration_after_request_check(
          conn,
          device_registration,
          session,
          params
        )
    end
  end

  defp approve_request_error(session, id, params) do
    expected_surface =
      if session.is_recovery, do: "recovery_device_approval", else: "device_approval"

    cond do
      session.is_recovery and session.device_registration_id != id ->
        :recovery_self_approval_only

      session.is_recovery and recovery_approval_contains_delivery_fields?(params) ->
        :invalid_recovery_approval

      params["approval_signature_surface"] != expected_surface ->
        :invalid_approval_surface

      not is_map(params["approval_proof"]) ->
        :invalid_approval_proof

      true ->
        :ok
    end
  end

  defp approve_owned_device_registration_after_request_check(
         conn,
         device_registration,
         session,
         params
       ) do
    case decode_hybrid_signature(
           params["approval_signature"],
           :approval_signature
         ) do
      {:ok, approval_signature} ->
        approve_owned_device_registration_with_signature(
          conn,
          device_registration,
          approval_signature,
          session,
          params
        )

      {:error, :invalid_approval_signature} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_signature"})
    end
  end

  defp approve_owned_device_registration_with_signature(
         conn,
         device_registration,
         approval_signature,
         session,
         params
       ) do
    params = RegistrationPayload.normalize_approval_delivery_artifacts(params)

    with {:ok, approval_commitments, approval_artifacts} <-
           Devices.prepare_device_approval_inputs(
             params,
             session.is_recovery,
             conn.assigns[:rrp_device],
             device_registration
           ),
         result <-
           Devices.approve_device_registration(device_registration, approval_signature,
             is_recovery: session.is_recovery,
             approver_device_id: conn.assigns[:rrp_device_id],
             recovery_session_id: session.id,
             recovery_context: %{
               recovery_session_transcript_hash: session.recovery_session_transcript_hash,
               recovery_capability_hash: session.recovery_capability_hash,
               pending_registration_binding_hash: session.pending_registration_binding_hash,
               target_key_checkpoint_sequence: session.target_key_checkpoint_sequence,
               target_key_checkpoint_hash: session.target_key_checkpoint_hash,
               candidate_user_checkpoint_sequence: session.candidate_user_checkpoint_sequence,
               candidate_user_checkpoint_hash: session.candidate_user_checkpoint_hash
             },
             approval_commitments: approval_commitments,
             approval_artifacts: approval_artifacts,
             approval_proof_override: params["approval_proof"],
             key_directory: %{
               user_events: params["user_key_directory_events"],
               user_checkpoint: params["user_key_directory_checkpoint"],
               workspace_appends: params["workspace_key_directory_appends"]
             }
           ) do
      approval_registration_result_response(conn, result, session)
    else
      {:error, :invalid_approval_commitments} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_approval_commitments"})
    end
  end

  defp approval_registration_result_response(conn, {:ok, device}, session) do
    case bind_recovery_session_after_approval(conn, session, device) do
      {:ok, conn} ->
        conn
        |> put_status(:ok)
        |> json(%{device: approval_device_response(device)})

      {:error, reason} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: Atom.to_string(reason)})
    end
  end

  defp approval_registration_result_response(conn, {:error, :invalid_signature}, _session) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "invalid_signature"})
  end

  defp approval_registration_result_response(conn, {:error, reason}, _session)
       when is_atom(reason) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: Atom.to_string(reason)})
  end

  defp bind_recovery_session_after_approval(conn, %{is_recovery: true} = session, device) do
    case Auth.bind_session_to_device(session.id, device.id) do
      {1, _} ->
        {:ok, assign_recovered_device_session(conn, session, device.id)}

      {0, _} ->
        case Auth.get_session(session.id) do
          %{device_id: device_id, is_recovery: false} when device_id == device.id ->
            {:ok, assign_recovered_device_session(conn, session, device.id)}

          _ ->
            {:error, :recovery_session_device_bind_failed}
        end
    end
  end

  defp bind_recovery_session_after_approval(conn, _session, _device), do: {:ok, conn}

  defp assign_recovered_device_session(conn, session, device_id) do
    conn
    |> assign(:current_session, %{session | device_id: device_id, is_recovery: false})
    |> assign(:device_verified, true)
  end

  defp decode_hybrid_signature(signature, _field) when is_map(signature) do
    {:ok, signature}
  end

  defp decode_hybrid_signature(_signature, field), do: {:error, :"invalid_#{field}"}

  defp recovery_approval_contains_delivery_fields?(params) do
    Enum.any?(
      [
        "umk_distribution_delivery_commitment",
        "trust_transfer_delivery_commitment",
        "device_approval_kek_initial_delivery_commitments",
        "umk_distribution_initial_delivery",
        "trust_transfer_initial_delivery",
        "device_approval_kek_initial_deliveries"
      ],
      &Map.has_key?(params, &1)
    )
  end

  defp approval_device_response(%RefMD.Devices.Device{} = device) do
    %{
      id: device.id,
      name: device.name,
      device_type: device.device_type,
      hybrid_encryption_public_key_material: device.hybrid_encryption_public_key_material,
      encryption_key_id: device.encryption_key_id,
      hybrid_signing_public_key_material: device.hybrid_signing_public_key_material,
      signing_key_id: device.signing_key_id,
      client_nonce: encode_binary(device.client_nonce),
      approval_signature: device.approval_signature,
      approval_signature_surface: device.approval_signature_surface,
      approval_proof: device.approval_proof,
      approval_delivery_commitments: device.approval_delivery_commitments,
      approval_delivery_artifacts:
        RegistrationPayload.denormalize_approval_delivery_artifacts(
          device.approval_delivery_artifacts
        ),
      key_checkpoint_sequence: device.key_checkpoint_sequence,
      key_checkpoint_hash: device.key_checkpoint_hash,
      created_at: device.created_at,
      last_seen_at: device.last_seen_at
    }
  end

  defp approval_device_response(%RefMD.Devices.DeviceRegistration{} = registration) do
    %{
      id: registration.id,
      name: registration.name,
      device_type: registration.device_type,
      hybrid_encryption_public_key_material: registration.hybrid_encryption_public_key_material,
      encryption_key_id: registration.encryption_key_id,
      hybrid_signing_public_key_material: registration.hybrid_signing_public_key_material,
      signing_key_id: registration.signing_key_id,
      client_nonce: encode_binary(registration.client_nonce),
      approval_signature: registration.approval_signature,
      approval_signature_surface: registration.approval_signature_surface,
      approval_proof: registration.approval_proof,
      approval_delivery_commitments: registration.approval_delivery_commitments,
      approval_delivery_artifacts:
        RegistrationPayload.denormalize_approval_delivery_artifacts(
          registration.approval_delivery_artifacts
        ),
      created_at: registration.created_at,
      last_seen_at: registration.created_at
    }
  end

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

  defp requires_reauth?(session) do
    if session.is_recovery, do: false, else: do_requires_reauth?(session)
  end

  defp do_requires_reauth?(session) do
    last_auth = session.last_verified_at || session.created_at
    DateTime.diff(DateTime.utc_now(), last_auth, :second) >= @reauth_max_age_seconds
  end
end
