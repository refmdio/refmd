defmodule RefMD.Devices.Registrations.Materials do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto
  alias RefMD.Crypto.{HybridEncryptionMaterial, Signature}
  alias RefMD.Encryption.UserIdentityPublicKey
  alias RefMD.Repo

  @spec validate_device_request_material(map()) :: :ok | {:error, atom()}
  def validate_device_request_material(material) do
    with :ok <-
           validate_device_keys(
             material.x25519_public_key,
             material.mlkem768_public_key,
             material.client_nonce
           ),
         :ok <-
           validate_device_encryption_material(
             material.hybrid_encryption_public_key_material,
             material.device_id,
             material.x25519_public_key,
             material.mlkem768_public_key,
             material.device_encryption_key_id
           ) do
      validate_device_material(
        material.hybrid_signing_public_key_material,
        material.device_id,
        material.device_signing_key_id
      )
    end
  end

  @spec validate_identity_signing_key_id(term(), term()) ::
          :ok | {:error, :invalid_identity_signing_key_id}
  def validate_identity_signing_key_id(user_id, identity_signing_key_id)
      when is_binary(user_id) and is_binary(identity_signing_key_id) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id and k.signing_key_id == ^identity_signing_key_id,
      select: true,
      limit: 1
    )
    |> Repo.exists?()
    |> case do
      true -> :ok
      false -> {:error, :invalid_identity_signing_key_id}
    end
  end

  def validate_identity_signing_key_id(_, _), do: {:error, :invalid_identity_signing_key_id}

  @spec validate_bootstrap_identity_material(term(), map()) ::
          :ok | {:error, :invalid_identity_hybrid_signing_public_key_material}
  def validate_bootstrap_identity_material(user_id, %{
        identity_signing_key_id: signing_key_id,
        identity_hybrid_signing_public_key_material: material
      })
      when is_binary(user_id) and is_binary(signing_key_id) and is_map(material) do
    with :ok <- Signature.assert_public_key_material!(material),
         true <- material["owner_kind"] == "identity",
         true <- material["owner_id"] == user_id,
         true <- Signature.compute_signing_key_id!(material) == signing_key_id,
         {:ok, stored_material} <- fetch_identity_signing_material(user_id, signing_key_id),
         true <- stored_material == material do
      :ok
    else
      _ -> {:error, :invalid_identity_hybrid_signing_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_identity_hybrid_signing_public_key_material}
  end

  def validate_bootstrap_identity_material(_, _),
    do: {:error, :invalid_identity_hybrid_signing_public_key_material}

  defp fetch_identity_signing_material(user_id, signing_key_id) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id and k.signing_key_id == ^signing_key_id,
      select: k.hybrid_signing_public_key_material,
      limit: 1
    )
    |> Repo.one()
    |> case do
      material when is_map(material) -> {:ok, material}
      _ -> :error
    end
  end

  defp validate_device_keys(x25519_public_key, mlkem768_public_key, client_nonce) do
    cond do
      byte_size(x25519_public_key) != 32 ->
        {:error, :invalid_device_hybrid_encryption_public_key_material}

      not Crypto.valid_x25519_public_key?(x25519_public_key) ->
        {:error, :invalid_device_hybrid_encryption_public_key_material}

      byte_size(mlkem768_public_key) != 1184 ->
        {:error, :invalid_mlkem768_public_key_size}

      byte_size(client_nonce) != 16 ->
        {:error, :invalid_client_nonce_size}

      true ->
        :ok
    end
  end

  defp validate_device_material(material, device_id, device_signing_key_id)
       when is_map(material) and is_binary(device_id) do
    with :ok <- Signature.assert_public_key_material!(material),
         true <- material["owner_kind"] == "device",
         true <- material["owner_id"] == device_id,
         true <- Signature.compute_signing_key_id!(material) == device_signing_key_id do
      :ok
    else
      _ -> {:error, :invalid_device_hybrid_signing_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_device_hybrid_signing_public_key_material}
  end

  defp validate_device_material(_, _, _),
    do: {:error, :invalid_device_hybrid_signing_public_key_material}

  defp validate_device_encryption_material(
         material,
         device_id,
         x25519_public_key,
         mlkem768_public_key,
         device_encryption_key_id
       )
       when is_map(material) and is_binary(device_id) do
    with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
         true <- material["owner_kind"] == "device",
         true <- material["owner_id"] == device_id,
         true <- HybridEncryptionMaterial.x25519_public!(material) == x25519_public_key,
         true <- HybridEncryptionMaterial.mlkem768_public!(material) == mlkem768_public_key,
         true <- HybridEncryptionMaterial.compute_key_id!(material) == device_encryption_key_id do
      :ok
    else
      _ -> {:error, :invalid_device_hybrid_encryption_public_key_material}
    end
  rescue
    ArgumentError -> {:error, :invalid_device_hybrid_encryption_public_key_material}
  end

  defp validate_device_encryption_material(_, _, _, _, _),
    do: {:error, :invalid_device_hybrid_encryption_public_key_material}
end
