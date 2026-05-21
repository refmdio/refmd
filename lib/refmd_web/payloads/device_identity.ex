defmodule RefMDWeb.Payloads.DeviceIdentity do
  @moduledoc false

  alias RefMD.Encryption
  alias RefMDWeb.Payloads.DeviceRegistration

  @spec sender_fields(nil | map()) :: map()
  def sender_fields(nil), do: %{}

  def sender_fields(device) do
    identity = Encryption.get_user_identity_public_key(device.user_id)

    %{
      sender_user_id: device.user_id,
      sender_hybrid_encryption_public_key_material: device.hybrid_encryption_public_key_material,
      sender_hybrid_signing_public_key_material: device.hybrid_signing_public_key_material,
      sender_identity_hybrid_encryption_public_key_material:
        identity && identity.hybrid_encryption_public_key_material,
      sender_identity_hybrid_signing_public_key_material:
        identity && identity.hybrid_signing_public_key_material,
      sender_approval_signature: device.approval_signature,
      sender_approval_signature_surface: device.approval_signature_surface,
      sender_approval_proof: device.approval_proof,
      sender_approval_delivery_commitments: device.approval_delivery_commitments,
      sender_approval_delivery_artifacts:
        DeviceRegistration.denormalize_approval_delivery_artifacts(
          device.approval_delivery_artifacts
        ),
      sender_client_nonce: encode_binary(device.client_nonce)
    }
  end

  @spec workspace_device_fields(map()) :: map()
  def workspace_device_fields(device) do
    identity = Encryption.get_user_identity_public_key(device.user_id)

    %{
      identity_hybrid_encryption_public_key_material:
        identity && identity.hybrid_encryption_public_key_material,
      identity_hybrid_signing_public_key_material:
        identity && identity.hybrid_signing_public_key_material,
      approval_signature: device.approval_signature,
      approval_signature_surface: device.approval_signature_surface,
      approval_proof: device.approval_proof,
      approval_delivery_commitments: device.approval_delivery_commitments,
      approval_delivery_artifacts:
        DeviceRegistration.denormalize_approval_delivery_artifacts(
          device.approval_delivery_artifacts
        ),
      client_nonce: encode_binary(device.client_nonce)
    }
  end

  defp encode_binary(nil), do: nil
  defp encode_binary(binary), do: Base.url_encode64(binary, padding: false)
end
