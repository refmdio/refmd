defmodule RefMDWeb.GuestInvitationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Crypto
  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, Signature}
  alias RefMD.Encryption
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC
  alias RefMDWeb.Schemas

  plug RequireRBAC,
       [permission: "guest:invite", not_member_status: :not_found]
       when action in [:index, :create, :delete]

  @max_expires_days 30
  @uuid_regex ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  operation(:create,
    summary: "Create a guest invitation",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Guest invitation params", "application/json", Schemas.CreateGuestInvitationRequest},
    responses: [
      created: {"Created guest invitation", "application/json", Schemas.GuestInvitationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec create(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create(conn, params) do
    workspace_id = conn.assigns.workspace_id
    user_id = conn.assigns.current_user_id
    actor_role = conn.assigns.workspace_role

    with {:ok, validated} <- validate_create_params(params, workspace_id, user_id),
         validated =
           validated
           |> Map.put(:actor_role, actor_role)
           |> Map.put(:actor_device_id, conn.assigns[:pop_device_id]),
         {:ok, invitation} <- Workspaces.create_guest_invitation(validated) do
      conn
      |> put_status(:created)
      |> json(serialize_invitation(invitation))
    else
      {:error, reason} -> handle_create_error(conn, reason)
    end
  end

  operation(:index,
    summary: "List guest invitations",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Guest invitation list", "application/json", Schemas.GuestInvitationsListResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec index(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def index(conn, _params) do
    invitations = Workspaces.list_guest_invitations(conn.assigns.workspace_id)
    json(conn, %{invitations: invitations})
  end

  operation(:delete,
    summary: "Revoke a guest invitation",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      invitation_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Revocation params", "application/json", Schemas.RevokeInvitationRequest},
    responses: [
      no_content: {"Revoked", "application/json", nil},
      bad_request: {"Invalid ID format", "application/json", Schemas.ErrorResponse},
      conflict: {"Guest invites disabled", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec delete(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def delete(conn, %{"invitation_id" => invitation_id} = params) do
    if Regex.match?(@uuid_regex, invitation_id) do
      case require_workspace_key_directory(params) do
        {:ok, key_directory} ->
          do_delete(conn, invitation_id, key_directory)

        {:error, reason} ->
          handle_create_error(conn, reason)
      end
    else
      conn |> put_status(:bad_request) |> json(%{error: "invalid_invitation_id_format"})
    end
  end

  defp do_delete(conn, invitation_id, key_directory) do
    key_directory = put_actor_device_id(key_directory, conn.assigns[:pop_device_id])

    case Workspaces.revoke_guest_invitation(
           conn.assigns.workspace_id,
           invitation_id,
           conn.assigns.current_user_id,
           key_directory
         ) do
      {:ok, _} ->
        send_resp(conn, :no_content, "")

      {:error, :guest_invites_disabled} ->
        conn |> put_status(:conflict) |> json(%{error: "guest_invites_disabled"})

      {:error, :permission_denied} ->
        conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})

      {:error, :serialization_failure} ->
        conn |> put_status(:conflict) |> json(%{error: "serialization_failure"})

      {:error, :invalid_key_directory} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})
    end
  end

  operation(:redeem,
    summary: "Redeem a guest invitation",
    request_body:
      {"Redeem guest invitation params", "application/json", Schemas.RedeemGuestInvitationRequest},
    responses: [
      ok:
        {"Redeemed guest invitation", "application/json", Schemas.RedeemGuestInvitationResponse},
      bad_request: {"Invalid", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Conflict", "application/json", Schemas.ErrorResponse},
      gone: {"Gone", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec redeem(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def redeem(conn, params) do
    with {:ok, validated} <- validate_redeem_params(params),
         {:ok, key_directory} <- require_workspace_key_directory(params),
         {:ok, token_hash} <- compute_token_hash(validated.token),
         {:ok, result} <-
           Workspaces.redeem_guest_invitation(
             token_hash,
             validated,
             %{
               ip_address: to_string(:inet_parse.ntoa(conn.remote_ip)),
               user_agent: get_req_header(conn, "user-agent") |> List.first()
             },
             key_directory
           ) do
      conn
      |> set_session_cookie(result.session_token, false)
      |> json(serialize_redeem_result(result))
    else
      {:error, reason} -> handle_redeem_error(conn, reason)
    end
  end

  @create_request_keys ~w(
    bootstrap_key_commitment
    bootstrap_package_hash
    bootstrap_package_key_maintenance_wrap
    bootstrap_package_key_recipient_wrap
    bootstrap_suite_id
    capability_context_hash
    encrypted_bootstrap_package
    expires_at
    invitation_id
    kek_version
    max_redemptions
    permission
    scope_id
    scope_kind
    token_hash
    token_prefix
    workspace_key_directory_checkpoint
    workspace_key_directory_events
  )

  defp validate_create_params(params, workspace_id, user_id) do
    body_params = Map.drop(params, ["workspace_id"])

    with :ok <-
           validate_exact_keys(
             body_params,
             @create_request_keys,
             :unexpected_guest_invitation_keys
           ),
         :ok <- validate_token_hash(body_params["token_hash"]),
         :ok <- validate_token_prefix(body_params["token_prefix"]),
         :ok <- validate_invitation_id(body_params["invitation_id"]),
         :ok <- validate_scope_kind(body_params["scope_kind"]),
         :ok <- validate_permission(body_params["permission"]),
         :ok <- validate_scope_id(body_params["scope_kind"], body_params["scope_id"]),
         :ok <- validate_positive_integer(body_params["kek_version"], :invalid_kek_version),
         :ok <- validate_commitment(body_params["bootstrap_key_commitment"]),
         {:ok, _bootstrap_package_hash} <-
           validate_hash(body_params["bootstrap_package_hash"], :invalid_bootstrap_package_hash),
         :ok <-
           validate_map(
             body_params["bootstrap_package_key_recipient_wrap"],
             :invalid_bootstrap_package_key_recipient_wrap
           ),
         :ok <-
           validate_map(
             body_params["bootstrap_package_key_maintenance_wrap"],
             :invalid_bootstrap_package_key_maintenance_wrap
           ),
         :ok <- validate_bootstrap_suite_id(body_params["bootstrap_suite_id"]),
         {:ok, _capability_context_hash} <-
           validate_hash(body_params["capability_context_hash"], :invalid_capability_context_hash),
         :ok <-
           validate_encrypted_bootstrap_package(
             body_params["encrypted_bootstrap_package"],
             workspace_id,
             body_params["kek_version"],
             body_params["scope_kind"],
             body_params["scope_id"]
           ),
         :ok <-
           validate_optional_positive_integer(
             body_params["max_redemptions"],
             :invalid_max_redemptions
           ),
         :ok <- validate_expires_at(body_params["expires_at"]),
         {:ok, key_directory} <- require_workspace_key_directory(body_params) do
      {:ok,
       %{
         workspace_id: workspace_id,
         invitation_id: body_params["invitation_id"],
         token_hash: body_params["token_hash"],
         token_prefix: body_params["token_prefix"],
         scope_kind: body_params["scope_kind"],
         scope_id: body_params["scope_id"],
         permission: body_params["permission"],
         kek_version: body_params["kek_version"],
         bootstrap_key_commitment: body_params["bootstrap_key_commitment"],
         encrypted_bootstrap_package: body_params["encrypted_bootstrap_package"],
         bootstrap_package_hash: body_params["bootstrap_package_hash"],
         bootstrap_package_key_recipient_wrap:
           body_params["bootstrap_package_key_recipient_wrap"],
         bootstrap_package_key_maintenance_wrap:
           body_params["bootstrap_package_key_maintenance_wrap"],
         bootstrap_suite_id: body_params["bootstrap_suite_id"],
         capability_context_hash: body_params["capability_context_hash"],
         max_redemptions: body_params["max_redemptions"],
         invited_by: user_id,
         expires_at: parse_expires_at(body_params["expires_at"]),
         key_directory: key_directory
       }}
    end
  end

  defp validate_redeem_params(params) do
    with {:ok, token} <- decode_token(params["token"]),
         :ok <- validate_guest_user_id(params["guest_user_id"]),
         :ok <- validate_device_id(params["device_id"]),
         {:ok, device_hybrid_encryption_public_key_material} <-
           validate_device_encryption_material(
             params["device_hybrid_encryption_public_key_material"],
             params["device_id"]
           ),
         {:ok, device_x25519_public_key} <-
           encryption_material_x25519_public(device_hybrid_encryption_public_key_material),
         {:ok, identity_hybrid_encryption_public_key_material} <-
           optional_identity_encryption_material(
             params["identity_hybrid_encryption_public_key_material"],
             params["guest_user_id"],
             device_hybrid_encryption_public_key_material
           ),
         {:ok, identity_x25519_public_key} <-
           encryption_material_x25519_public(identity_hybrid_encryption_public_key_material),
         {:ok, approval_signature} <-
           decode_hybrid_signature(
             params["approval_signature"],
             :approval_signature
           ),
         {:ok, pending_registration_challenge_hash} <-
           validate_hash(
             params["pending_registration_challenge_hash"],
             :pending_registration_challenge_hash
           ),
         {:ok, client_nonce} <- decode_base64url(params["client_nonce"], :client_nonce),
         :ok <- validate_byte_length(client_nonce, 16, :invalid_client_nonce_length),
         :ok <-
           validate_encryption_key(
             device_x25519_public_key,
             :invalid_device_hybrid_encryption_public_key_material
           ),
         :ok <-
           validate_encryption_key(
             identity_x25519_public_key,
             :invalid_identity_hybrid_encryption_public_key_material
           ),
         {:ok, device_hybrid_signing_public_key_material} <-
           validate_device_signing_material(
             params["device_hybrid_signing_public_key_material"],
             params["device_id"]
           ),
         {:ok, identity_hybrid_signing_public_key_material} <-
           optional_identity_signing_material(
             params["identity_hybrid_signing_public_key_material"],
             params["guest_user_id"],
             device_hybrid_signing_public_key_material
           ),
         :ok <- validate_key_directory(params),
         :ok <- validate_optional_device_name(params["device_name"]),
         :ok <- validate_optional_device_type(params["device_type"]) do
      {:ok,
       %{
         token: token,
         guest_user_id: params["guest_user_id"],
         device_id: params["device_id"],
         device_hybrid_encryption_public_key_material:
           device_hybrid_encryption_public_key_material,
         device_hybrid_signing_public_key_material: device_hybrid_signing_public_key_material,
         identity_hybrid_encryption_public_key_material:
           identity_hybrid_encryption_public_key_material,
         identity_hybrid_signing_public_key_material: identity_hybrid_signing_public_key_material,
         approval_signature: approval_signature,
         pending_registration_challenge_hash: pending_registration_challenge_hash,
         client_nonce: client_nonce,
         identity_encryption_key_id:
           HybridEncryptionMaterial.compute_key_id!(
             identity_hybrid_encryption_public_key_material
           ),
         identity_signing_key_id:
           Signature.compute_signing_key_id!(identity_hybrid_signing_public_key_material),
         device_name: params["device_name"],
         device_type: params["device_type"]
       }}
    end
  end

  defp validate_exact_keys(params, keys, reason) when is_map(params) do
    extras = Map.keys(params) -- keys
    if extras == [], do: :ok, else: {:error, reason}
  end

  defp serialize_invitation(invitation) do
    %{
      invitation_id: invitation.id,
      workspace_id: invitation.workspace_id,
      token_prefix: invitation.token_prefix,
      scope_kind: invitation.scope_kind,
      scope_id: invitation.scope_id,
      permission: invitation.permission,
      invited_by: invitation.invited_by,
      kek_version: invitation.kek_version,
      bootstrap_key_commitment: invitation.bootstrap_key_commitment,
      encrypted_bootstrap_package: invitation.encrypted_bootstrap_package,
      bootstrap_package_hash: invitation.bootstrap_package_hash,
      bootstrap_package_key_recipient_wrap: invitation.bootstrap_package_key_recipient_wrap,
      bootstrap_package_key_maintenance_wrap: invitation.bootstrap_package_key_maintenance_wrap,
      bootstrap_suite_id: invitation.bootstrap_suite_id,
      capability_context_hash: invitation.capability_context_hash,
      max_redemptions: invitation.max_redemptions,
      redemption_count: invitation.redemption_count,
      expires_at: invitation.expires_at,
      created_at: invitation.created_at,
      revoked_at: invitation.revoked_at
    }
  end

  defp serialize_redeem_result(result) do
    %{
      workspace_id: result.workspace_id,
      workspace_name: result.workspace_name,
      invitation_id: result.invitation_id,
      scope_kind: result.scope_kind,
      scope_id: result.scope_id,
      permission: result.permission,
      guest_user_id: result.guest_user_id,
      guest_device_id: result.guest_device_id,
      kek_version: result.kek_version,
      workspace_key_directory_checkpoint:
        serialize_checkpoint(
          Encryption.current_workspace_key_directory_checkpoint(result.workspace_id)
        )
    }
  end

  defp serialize_checkpoint(nil), do: nil

  defp serialize_checkpoint(checkpoint) do
    %{payload: checkpoint.payload, signatures: checkpoint.signatures}
  end

  defp decode_base64url(nil, field), do: {:error, {:invalid_format, field}}

  defp decode_base64url(value, field) when not is_binary(value),
    do: {:error, {:invalid_format, field}}

  defp decode_base64url(value, field) do
    {:ok, Encoding.decode_base64url!(value)}
  rescue
    ArgumentError -> {:error, {:invalid_format, field}}
  end

  defp decode_token(nil), do: {:error, :missing_token}
  defp decode_token(token) when not is_binary(token), do: {:error, :invalid_token_format}

  defp decode_token(token) do
    bytes = Encoding.decode_base64url!(token)
    if byte_size(bytes) == 32, do: {:ok, bytes}, else: {:error, :invalid_token_length}
  rescue
    ArgumentError -> {:error, :invalid_token_format}
  end

  defp compute_token_hash(token_bytes) do
    {:ok, Base.url_encode64(:crypto.hash(:sha256, token_bytes), padding: false)}
  end

  defp validate_byte_length(bytes, expected, error_atom) do
    if byte_size(bytes) == expected, do: :ok, else: {:error, error_atom}
  end

  defp validate_encryption_key(key, error_atom) do
    if Crypto.valid_x25519_public_key?(key),
      do: :ok,
      else: {:error, error_atom}
  end

  defp decode_hybrid_signature(signature, _field) when is_map(signature) do
    {:ok, signature}
  end

  defp decode_hybrid_signature(_signature, field), do: {:error, :"invalid_#{field}"}

  defp validate_device_signing_material(material, device_id)
       when is_map(material) and is_binary(device_id) do
    with :ok <- Signature.assert_public_key_material!(material),
         true <- material["owner_kind"] == "device",
         true <- material["owner_id"] == device_id do
      {:ok, material}
    else
      _ -> {:error, :invalid_device_hybrid_signing_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_device_hybrid_signing_public_key_material}
  end

  defp validate_device_signing_material(_, _),
    do: {:error, :invalid_device_hybrid_signing_public_key_material}

  defp validate_identity_signing_material(material, user_id)
       when is_map(material) and is_binary(user_id) do
    with :ok <- Signature.assert_public_key_material!(material),
         true <- material["owner_kind"] == "identity",
         true <- material["owner_id"] == user_id do
      {:ok, material}
    else
      _ -> {:error, :invalid_identity_hybrid_signing_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_identity_hybrid_signing_public_key_material}
  end

  defp validate_identity_signing_material(_, _),
    do: {:error, :invalid_identity_hybrid_signing_public_key_material}

  defp optional_identity_signing_material(nil, _user_id, fallback), do: {:ok, fallback}

  defp optional_identity_signing_material(material, user_id, _fallback),
    do: validate_identity_signing_material(material, user_id)

  defp validate_device_encryption_material(material, device_id)
       when is_map(material) and is_binary(device_id) do
    with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
         true <- material["owner_kind"] == "device",
         true <- material["owner_id"] == device_id do
      {:ok, material}
    else
      _ -> {:error, :invalid_device_hybrid_encryption_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_device_hybrid_encryption_public_key_material}
  end

  defp validate_device_encryption_material(_, _),
    do: {:error, :invalid_device_hybrid_encryption_public_key_material}

  defp validate_identity_encryption_material(material, user_id)
       when is_map(material) and is_binary(user_id) do
    with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
         true <- material["owner_kind"] == "identity",
         true <- material["owner_id"] == user_id do
      {:ok, material}
    else
      _ -> {:error, :invalid_identity_hybrid_encryption_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_identity_hybrid_encryption_public_key_material}
  end

  defp validate_identity_encryption_material(_, _),
    do: {:error, :invalid_identity_hybrid_encryption_public_key_material}

  defp optional_identity_encryption_material(nil, _user_id, fallback), do: {:ok, fallback}

  defp optional_identity_encryption_material(material, user_id, _fallback),
    do: validate_identity_encryption_material(material, user_id)

  defp encryption_material_x25519_public(material) do
    {:ok, HybridEncryptionMaterial.x25519_public!(material)}
  rescue
    ArgumentError -> {:error, :invalid_hybrid_encryption_public_key_material}
  end

  defp validate_key_directory(%{
         "workspace_key_directory_events" => events,
         "workspace_key_directory_checkpoint" => checkpoint
       })
       when is_list(events) and is_map(checkpoint),
       do: :ok

  defp validate_key_directory(_params), do: {:error, :missing_key_directory}

  defp require_workspace_key_directory(params) do
    events = params["workspace_key_directory_events"]

    checkpoint = params["workspace_key_directory_checkpoint"]

    cond do
      is_nil(events) and is_nil(checkpoint) ->
        {:error, :missing_key_directory}

      is_list(events) and is_map(checkpoint) ->
        {:ok, %{events: events, checkpoint: checkpoint}}

      true ->
        {:error, :invalid_key_directory}
    end
  end

  defp put_actor_device_id(key_directory, actor_device_id),
    do: Map.put(key_directory, :actor_device_id, actor_device_id)

  defp validate_token_hash(nil), do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) when not is_binary(hash),
    do: {:error, :invalid_token_hash_format}

  defp validate_token_hash(hash) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, hash),
      do: :ok,
      else: {:error, :invalid_token_hash_format}
  end

  defp validate_commitment(value) when is_binary(value) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{43}$/, value),
      do: :ok,
      else: {:error, :invalid_bootstrap_key_commitment}
  end

  defp validate_commitment(_), do: {:error, :invalid_bootstrap_key_commitment}

  defp validate_map(value, _reason) when is_map(value), do: :ok
  defp validate_map(_value, reason), do: {:error, reason}

  defp validate_bootstrap_suite_id("refmd-v2-invitation-bootstrap-xchacha20poly1305"), do: :ok
  defp validate_bootstrap_suite_id(_), do: {:error, :invalid_bootstrap_suite_id}

  defp validate_encrypted_bootstrap_package(
         package,
         workspace_id,
         key_version,
         scope_kind,
         scope_kind_id
       )
       when is_map(package) and is_integer(key_version) do
    with encrypted_payload when is_map(encrypted_payload) <- package["encrypted_payload"],
         recipient_wrap when is_map(recipient_wrap) <- package["package_key_recipient_wrap"],
         aad when is_map(aad) <- package["aad"],
         key_context when is_map(key_context) <- aad["key_version_context"],
         maintenance_wrap = package["package_key_maintenance_wrap"],
         true <- exact_keys?(package, guest_encrypted_bootstrap_package_keys(scope_kind)),
         true <- exact_keys?(encrypted_payload, ["ciphertext", "nonce"]),
         true <- exact_keys?(recipient_wrap, ["ciphertext", "nonce"]),
         true <-
           exact_keys?(aad, [
             "guest_invitation_id",
             "key_version_context",
             "permission",
             "protocol",
             "scope_id",
             "scope_kind",
             "suite_id",
             "token_hash",
             "version",
             "workspace_id"
           ]),
         true <-
           exact_keys?(key_context, [
             "dek_version",
             "share_key_version",
             "workspace_kek_version"
           ]),
         true <- package["protocol"] == "refmd.guest-invitation-bootstrap",
         true <- package["version"] == 1,
         true <- package["suite_id"] == "refmd-v2-invitation-bootstrap-xchacha20poly1305",
         true <- package["workspace_id"] == workspace_id,
         true <- package["key_version"] == key_version,
         true <- aad["protocol"] == package["protocol"],
         true <- aad["version"] == 1,
         true <- aad["suite_id"] == package["suite_id"],
         true <- aad["workspace_id"] == workspace_id,
         true <- guest_bootstrap_key_context_valid?(scope_kind, key_context, key_version),
         true <- is_binary(aad["guest_invitation_id"]),
         true <- aad["scope_kind"] == scope_kind,
         true <- aad["scope_id"] == guest_bootstrap_scope_id(scope_kind, scope_kind_id),
         true <- aad["permission"] in ["view", "edit"],
         true <- is_binary(aad["token_hash"]),
         :ok <- validate_base64url_bytes(recipient_wrap["nonce"], 24),
         :ok <- validate_base64url_min_bytes(recipient_wrap["ciphertext"], 48),
         :ok <- validate_base64url_bytes(encrypted_payload["nonce"], 24),
         :ok <- validate_base64url_min_bytes(encrypted_payload["ciphertext"], 128),
         :ok <-
           validate_guest_bootstrap_maintenance_wrap(
             scope_kind,
             maintenance_wrap,
             key_version,
             key_context
           ) do
      :ok
    else
      _ -> {:error, :invalid_encrypted_bootstrap_package}
    end
  end

  defp validate_encrypted_bootstrap_package(
         _package,
         _workspace_id,
         _key_version,
         _scope_kind,
         _target_id
       ),
       do: {:error, :invalid_encrypted_bootstrap_package}

  defp guest_bootstrap_scope_id("workspace", _scope_id), do: "none"
  defp guest_bootstrap_scope_id(_scope_kind, scope_id), do: scope_id

  defp guest_encrypted_bootstrap_package_keys("workspace") do
    [
      "aad",
      "encrypted_payload",
      "key_version",
      "package_key_maintenance_wrap",
      "package_key_recipient_wrap",
      "protocol",
      "suite_id",
      "version",
      "workspace_id"
    ]
  end

  defp guest_encrypted_bootstrap_package_keys(_scope),
    do: guest_encrypted_bootstrap_package_keys("workspace")

  defp guest_bootstrap_key_context_valid?("workspace", key_context, key_version) do
    key_context["workspace_kek_version"] == key_version and
      key_context["share_key_version"] == "NOT_APPLICABLE" and
      key_context["dek_version"] == "NOT_APPLICABLE"
  end

  defp guest_bootstrap_key_context_valid?(scope, key_context, _key_version)
       when scope in ["document", "folder", "share"] do
    key_context["workspace_kek_version"] == "NOT_APPLICABLE" and
      scoped_guest_key_version?(key_context["share_key_version"]) and
      scoped_guest_key_version?(key_context["dek_version"]) and
      (positive_integer?(key_context["share_key_version"]) or
         positive_integer?(key_context["dek_version"]))
  end

  defp guest_bootstrap_key_context_valid?(_, _, _), do: false

  defp validate_guest_bootstrap_maintenance_wrap(
         "workspace",
         maintenance_wrap,
         key_version,
         key_context
       )
       when is_map(maintenance_wrap) do
    with true <- exact_keys?(maintenance_wrap, ["ciphertext", "key_version", "nonce"]),
         true <- maintenance_wrap["key_version"] == key_version,
         true <- key_context["workspace_kek_version"] == key_version,
         :ok <- validate_base64url_bytes(maintenance_wrap["nonce"], 24),
         :ok <- validate_base64url_min_bytes(maintenance_wrap["ciphertext"], 48) do
      :ok
    else
      _ -> {:error, :invalid_encrypted_bootstrap_package}
    end
  end

  defp validate_guest_bootstrap_maintenance_wrap(
         "workspace",
         _maintenance_wrap,
         _key_version,
         _key_context
       ),
       do: {:error, :invalid_encrypted_bootstrap_package}

  defp validate_guest_bootstrap_maintenance_wrap(
         scope,
         maintenance_wrap,
         key_version,
         key_context
       )
       when scope in ["document", "folder", "share"] and is_map(maintenance_wrap) do
    with true <- exact_keys?(maintenance_wrap, ["ciphertext", "key_version", "nonce"]),
         true <- maintenance_wrap["key_version"] == key_version,
         true <- scoped_guest_maintenance_key_version?(key_version, key_context),
         :ok <- validate_base64url_bytes(maintenance_wrap["nonce"], 24),
         :ok <- validate_base64url_min_bytes(maintenance_wrap["ciphertext"], 48) do
      :ok
    else
      _ -> {:error, :invalid_encrypted_bootstrap_package}
    end
  end

  defp validate_guest_bootstrap_maintenance_wrap(
         scope,
         _maintenance_wrap,
         _key_version,
         _key_context
       )
       when scope in ["document", "folder", "share"],
       do: {:error, :invalid_encrypted_bootstrap_package}

  defp scoped_guest_maintenance_key_version?(key_version, key_context) do
    key_context["workspace_kek_version"] == "NOT_APPLICABLE" and
      Enum.any?([key_context["share_key_version"], key_context["dek_version"]], fn
        ^key_version -> true
        _ -> false
      end)
  end

  defp exact_keys?(map, keys) when is_map(map),
    do: Map.keys(map) |> Enum.sort() == Enum.sort(keys)

  defp scoped_guest_key_version?("NOT_APPLICABLE"), do: true
  defp scoped_guest_key_version?(value), do: positive_integer?(value)

  defp positive_integer?(value), do: is_integer(value) and value > 0

  defp validate_base64url_bytes(value, byte_size) when is_binary(value) do
    Encoding.decode_base64url!(value, byte_size)
    :ok
  rescue
    ArgumentError -> {:error, :invalid_encrypted_bootstrap_package}
  end

  defp validate_base64url_bytes(_, _), do: {:error, :invalid_encrypted_bootstrap_package}

  defp validate_base64url_min_bytes(value, min_byte_size) when is_binary(value) do
    bytes = Encoding.decode_base64url!(value)

    if byte_size(bytes) >= min_byte_size,
      do: :ok,
      else: {:error, :invalid_encrypted_bootstrap_package}
  rescue
    ArgumentError -> {:error, :invalid_encrypted_bootstrap_package}
  end

  defp validate_base64url_min_bytes(_, _), do: {:error, :invalid_encrypted_bootstrap_package}

  defp validate_token_prefix(nil), do: {:error, :invalid_token_prefix}

  defp validate_token_prefix(prefix) when not is_binary(prefix),
    do: {:error, :invalid_token_prefix}

  defp validate_token_prefix(prefix) do
    if Regex.match?(~r/^[A-Za-z0-9\-_]{4}$/, prefix),
      do: :ok,
      else: {:error, :invalid_token_prefix}
  end

  defp validate_invitation_id(nil), do: {:error, :invalid_invitation_id_format}

  defp validate_invitation_id(id) when not is_binary(id),
    do: {:error, :invalid_invitation_id_format}

  defp validate_invitation_id(id) do
    if Regex.match?(@uuid_regex, id), do: :ok, else: {:error, :invalid_invitation_id_format}
  end

  defp validate_guest_user_id(nil), do: {:error, :invalid_guest_user_id_format}

  defp validate_guest_user_id(id) when not is_binary(id),
    do: {:error, :invalid_guest_user_id_format}

  defp validate_guest_user_id(id) do
    if Regex.match?(@uuid_regex, id), do: :ok, else: {:error, :invalid_guest_user_id_format}
  end

  defp validate_device_id(nil), do: {:error, :invalid_device_id_format}

  defp validate_device_id(id) when not is_binary(id),
    do: {:error, :invalid_device_id_format}

  defp validate_device_id(id) do
    if Regex.match?(@uuid_regex, id), do: :ok, else: {:error, :invalid_device_id_format}
  end

  defp validate_scope_kind(scope) when scope in ["workspace", "document", "folder", "share"],
    do: :ok

  defp validate_scope_kind(_scope), do: {:error, :invalid_scope_kind}

  defp validate_permission(permission) when permission in ["view", "edit"], do: :ok
  defp validate_permission(_permission), do: {:error, :invalid_permission}

  defp validate_scope_id("workspace", nil), do: :ok

  defp validate_scope_id(scope, id) when scope in ["document", "folder", "share"],
    do: validate_invitation_id(id)

  defp validate_scope_id(_scope, _id), do: {:error, :invalid_scope_id}

  defp validate_positive_integer(value, _error_atom) when is_integer(value) and value > 0, do: :ok
  defp validate_positive_integer(_value, error_atom), do: {:error, error_atom}

  defp validate_optional_positive_integer(nil, _error_atom), do: :ok

  defp validate_optional_positive_integer(value, error_atom),
    do: validate_positive_integer(value, error_atom)

  defp validate_optional_device_name(nil), do: :ok
  defp validate_optional_device_name(name) when is_binary(name) and byte_size(name) > 0, do: :ok
  defp validate_optional_device_name(_name), do: {:error, :invalid_device_name}

  defp validate_optional_device_type(nil), do: :ok
  defp validate_optional_device_type(type) when type in ["browser", "desktop", "mobile"], do: :ok
  defp validate_optional_device_type(_type), do: {:error, :invalid_device_type}

  defp validate_hash(value, error_atom) when is_binary(value) do
    Hash.assert_blake3_base64url!(value)
    {:ok, value}
  rescue
    ArgumentError -> {:error, error_atom}
  end

  defp validate_hash(_, error_atom), do: {:error, error_atom}

  defp validate_expires_at(nil), do: :ok

  defp validate_expires_at(expires_at_str) when not is_binary(expires_at_str),
    do: {:error, :invalid_expires_at}

  defp validate_expires_at(expires_at_str) do
    case DateTime.from_iso8601(expires_at_str) do
      {:ok, dt, _} ->
        now = DateTime.utc_now()
        max_dt = DateTime.add(now, @max_expires_days * 86_400)

        cond do
          DateTime.compare(dt, now) != :gt -> {:error, :invalid_expires_at}
          DateTime.compare(dt, max_dt) == :gt -> {:error, :invalid_expires_at}
          true -> :ok
        end

      _ ->
        {:error, :invalid_expires_at}
    end
  end

  defp parse_expires_at(nil), do: nil

  defp parse_expires_at(str) do
    {:ok, dt, _} = DateTime.from_iso8601(str)
    dt
  end

  defp handle_create_error(conn, {:invalid_format, _field}),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_format"})

  defp handle_create_error(conn, :workspace_not_found),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp handle_create_error(conn, :guest_invites_disabled),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_invites_disabled"})

  defp handle_create_error(conn, :kek_rotation_in_progress),
    do: conn |> put_status(:conflict) |> json(%{error: "kek_rotation_in_progress"})

  defp handle_create_error(conn, :encryption_setup_incomplete),
    do: conn |> put_status(:conflict) |> json(%{error: "encryption_setup_incomplete"})

  defp handle_create_error(conn, :kek_version_mismatch),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "kek_version_mismatch"})

  defp handle_create_error(conn, :invalid_scope),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_scope"})

  defp handle_create_error(conn, :token_hash_already_exists),
    do: conn |> put_status(:conflict) |> json(%{error: "token_hash_already_exists"})

  defp handle_create_error(conn, :id_already_exists),
    do: conn |> put_status(:conflict) |> json(%{error: "id_already_exists"})

  defp handle_create_error(conn, :permission_escalation),
    do: conn |> put_status(:forbidden) |> json(%{error: "permission_escalation"})

  defp handle_create_error(conn, :permission_denied),
    do: conn |> put_status(:forbidden) |> json(%{error: "permission_denied"})

  defp handle_create_error(conn, :serialization_failure),
    do: conn |> put_status(:conflict) |> json(%{error: "serialization_failure"})

  defp handle_create_error(conn, :invalid_key_directory),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})

  defp handle_create_error(conn, :missing_key_directory),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_key_directory"})

  defp handle_create_error(conn, :invalid_bootstrap_key_commitment),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_bootstrap_key_commitment"})

  defp handle_create_error(conn, :unexpected_guest_invitation_keys),
    do: conn |> put_status(:bad_request) |> json(%{error: "unexpected_guest_invitation_keys"})

  defp handle_create_error(conn, :invalid_encrypted_bootstrap_package),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_encrypted_bootstrap_package"})

  defp handle_create_error(conn, reason),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})

  defp handle_redeem_error(conn, :missing_token),
    do: conn |> put_status(:bad_request) |> json(%{error: "missing_token"})

  defp handle_redeem_error(conn, :invalid_token_format),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_token_format"})

  defp handle_redeem_error(conn, :invalid_token_length),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_token_length"})

  defp handle_redeem_error(conn, :invalid_bootstrap_key_commitment),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_bootstrap_key_commitment"})

  defp handle_redeem_error(conn, :invalid_guest_user_id_format),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_guest_user_id_format"})

  defp handle_redeem_error(conn, {:invalid_format, _field}),
    do: conn |> put_status(:bad_request) |> json(%{error: "invalid_format"})

  defp handle_redeem_error(conn, :not_found),
    do: conn |> put_status(:not_found) |> json(%{error: "not_found"})

  defp handle_redeem_error(conn, :guest_invites_disabled),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_invites_disabled"})

  defp handle_redeem_error(conn, :guest_member_limit_reached),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_member_limit_reached"})

  defp handle_redeem_error(conn, :guest_user_id_conflict),
    do: conn |> put_status(:conflict) |> json(%{error: "guest_user_id_conflict"})

  defp handle_redeem_error(conn, :active_user_session),
    do: conn |> put_status(:conflict) |> json(%{error: "active_user_session"})

  defp handle_redeem_error(conn, :kek_rotation_in_progress),
    do: conn |> put_status(:conflict) |> json(%{error: "kek_rotation_in_progress"})

  defp handle_redeem_error(conn, :invitation_revoked),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_revoked"})

  defp handle_redeem_error(conn, :invitation_expired),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_expired"})

  defp handle_redeem_error(conn, :invitation_redemptions_exhausted),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_redemptions_exhausted"})

  defp handle_redeem_error(conn, :invitation_kek_outdated),
    do: conn |> put_status(:gone) |> json(%{error: "invitation_kek_outdated"})

  defp handle_redeem_error(conn, :invalid_key_directory),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})

  defp handle_redeem_error(conn, :missing_key_directory),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_key_directory"})

  defp handle_redeem_error(conn, reason),
    do: conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
end
