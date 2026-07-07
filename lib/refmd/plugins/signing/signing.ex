defmodule RefMD.Plugins.Signing do
  @moduledoc false

  alias RefMD.Crypto.Signature
  alias RefMD.Devices.Device
  alias RefMD.Repo

  def fetch_active_device(user_id, device_id)
      when is_binary(user_id) and is_binary(device_id) do
    case Repo.get(Device, device_id) do
      %Device{
        user_id: ^user_id,
        revoked_at: nil,
        hybrid_signing_public_key_material: material,
        signing_key_id: signing_key_id
      } = device
      when is_map(material) and is_binary(signing_key_id) ->
        verify_signing_key_id(device, material, signing_key_id)

      _ ->
        {:error, :signing_device_not_found}
    end
  rescue
    ArgumentError -> {:error, :signing_key_invalid}
  end

  def fetch_active_device(_user_id, _device_id), do: {:error, :signing_device_not_found}

  def fetch_device(user_id, device_id)
      when is_binary(user_id) and is_binary(device_id) do
    case Repo.get(Device, device_id) do
      %Device{
        user_id: ^user_id,
        hybrid_signing_public_key_material: material,
        signing_key_id: signing_key_id
      } = device
      when is_map(material) and is_binary(signing_key_id) ->
        verify_signing_key_id(device, material, signing_key_id)

      _ ->
        {:error, :signing_device_not_found}
    end
  rescue
    ArgumentError -> {:error, :signing_key_invalid}
  end

  def fetch_device(_user_id, _device_id), do: {:error, :signing_device_not_found}

  def signing_key_id(device_id) do
    case Repo.get(Device, device_id) do
      %Device{signing_key_id: signing_key_id} -> signing_key_id
      _ -> nil
    end
  end

  def actor(%Device{} = device, scope_id, scope_kind \\ "workspace") do
    %{
      "device_id" => device.id,
      "key_checkpoint_hash" => device.key_checkpoint_hash,
      "key_checkpoint_sequence" => device.key_checkpoint_sequence,
      "key_scope_id" => scope_id,
      "key_scope_kind" => scope_kind,
      "signer_kind" => "device",
      "user_id" => device.user_id,
      "signing_key_id" => device.signing_key_id
    }
  end

  def verify(signing_purpose, transcript, signature, device, semantic_context)
      when is_binary(signing_purpose) and is_map(transcript) and is_map(signature) and
             is_map(semantic_context) do
    Signature.verify_hybrid_signature_result(
      signing_purpose,
      transcript,
      signature,
      device.hybrid_signing_public_key_material,
      semantic_context
    )
  end

  def verify(_, _, _, _, _), do: {:error, :invalid_signature}

  defp verify_signing_key_id(device, material, signing_key_id) do
    if Signature.compute_signing_key_id!(material) == signing_key_id do
      {:ok, device}
    else
      {:error, :signing_key_mismatch}
    end
  end
end
