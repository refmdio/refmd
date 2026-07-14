defmodule RefMDWeb.IdentityRotationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Crypto.Encoding
  alias RefMD.Encryption
  alias RefMDWeb.Schemas

  operation(:status,
    summary: "Get the current user identity rotation state",
    responses: [
      ok: {"Identity rotation state", "application/json", Schemas.IdentityRotationStatusResponse}
    ]
  )

  def status(conn, _params) do
    json(conn, rotation_status(conn.assigns.current_user_id))
  end

  operation(:prepare,
    summary: "Publish a pending identity successor",
    request_body:
      {"Identity successor", "application/json", Schemas.IdentityRotationPrepareRequest},
    responses: [
      ok: {"Identity rotation state", "application/json", Schemas.IdentityRotationStatusResponse},
      conflict: {"Rotation already pending", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Invalid rotation", "application/json", Schemas.ErrorResponse}
    ]
  )

  def prepare(conn, params) do
    user_id = conn.assigns.current_user_id

    attrs = %{
      public_key: %{
        hybrid_encryption_public_key_material: params["hybrid_encryption_public_key_material"],
        hybrid_signing_public_key_material: params["hybrid_signing_public_key_material"]
      },
      encrypted_key: %{
        encrypted_identity_hybrid_encryption_private_key_material:
          decode!(params["encrypted_identity_hybrid_encryption_private_key_material"]),
        identity_hybrid_encryption_private_key_material_nonce:
          decode!(params["identity_hybrid_encryption_private_key_material_nonce"]),
        encrypted_identity_hybrid_signing_private_key_material:
          decode!(params["encrypted_identity_hybrid_signing_private_key_material"]),
        identity_hybrid_signing_private_key_material_nonce:
          decode!(params["identity_hybrid_signing_private_key_material_nonce"])
      },
      user_key_directory_events: params["user_key_directory_events"],
      user_key_directory_checkpoint: params["user_key_directory_checkpoint"]
    }

    case Encryption.prepare_user_identity_rotation(user_id, attrs) do
      {:ok, _} ->
        json(conn, rotation_status(user_id))

      {:error, :identity_rotation_already_pending} ->
        error(conn, :conflict, "identity_rotation_already_pending")

      {:error, _} ->
        error(conn, :unprocessable_entity, "identity_rotation_invalid")
    end
  rescue
    ArgumentError -> error(conn, :unprocessable_entity, "identity_rotation_invalid")
  end

  operation(:activate,
    summary: "Durably activate an identity successor for key restore",
    request_body:
      {"Identity successor version", "application/json", Schemas.IdentityRotationActivateRequest},
    responses: [
      ok: {"Identity rotation state", "application/json", Schemas.IdentityRotationStatusResponse},
      unprocessable_entity: {"Rotation incomplete", "application/json", Schemas.ErrorResponse}
    ]
  )

  def activate(conn, %{"key_version" => key_version}) do
    user_id = conn.assigns.current_user_id

    case Encryption.activate_user_identity_rotation(user_id, key_version) do
      {:ok, _} -> json(conn, rotation_status(user_id))
      {:error, _} -> error(conn, :unprocessable_entity, "identity_rotation_incomplete")
    end
  end

  operation(:finalize,
    summary: "Finalize identity rotation after complete envelope rewrap and private-key deletion",
    request_body: {"Rotation proof", "application/json", Schemas.IdentityRotationFinalizeRequest},
    responses: [
      ok: {"Identity rotation state", "application/json", Schemas.IdentityRotationStatusResponse},
      unprocessable_entity: {"Rotation incomplete", "application/json", Schemas.ErrorResponse}
    ]
  )

  def finalize(conn, %{"key_version" => key_version, "deletion_proof" => proof} = params) do
    user_id = conn.assigns.current_user_id

    key_directory = %{
      events: params["user_key_directory_events"],
      checkpoint: params["user_key_directory_checkpoint"]
    }

    case Encryption.finalize_user_identity_rotation(user_id, key_version, proof, key_directory) do
      {:ok, _} -> json(conn, rotation_status(user_id))
      {:error, _} -> error(conn, :unprocessable_entity, "identity_rotation_incomplete")
    end
  end

  defp decode!(value), do: Encoding.decode_base64url!(value)

  defp rotation_status(user_id) do
    status = Encryption.user_identity_rotation_status(user_id)

    pending =
      status.pending_key_version &&
        Encryption.get_user_encrypted_identity_key_by_version(user_id, status.pending_key_version)

    Map.merge(status, %{
      pending_encrypted_identity_hybrid_encryption_private_key_material:
        encode(pending && pending.encrypted_identity_hybrid_encryption_private_key_material),
      pending_identity_hybrid_encryption_private_key_material_nonce:
        encode(pending && pending.identity_hybrid_encryption_private_key_material_nonce),
      pending_encrypted_identity_hybrid_signing_private_key_material:
        encode(pending && pending.encrypted_identity_hybrid_signing_private_key_material),
      pending_identity_hybrid_signing_private_key_material_nonce:
        encode(pending && pending.identity_hybrid_signing_private_key_material_nonce)
    })
  end

  defp encode(nil), do: nil
  defp encode(value), do: Encoding.encode_base64url(value)

  defp error(conn, status, code), do: conn |> put_status(status) |> json(%{error: code})
end
