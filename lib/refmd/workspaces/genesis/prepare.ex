defmodule RefMD.Workspaces.Genesis.Prepare do
  @moduledoc false

  alias RefMD.Auth.Genesis.Prepare, as: AccountGenesisPrepare
  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, JCS, Signature, Suite}
  alias RefMD.Devices
  alias RefMD.Encryption

  @keys ~w(
    description icon name owner_role_id protocol version workspace_id
    workspace_member_envelope_precommit
  )

  def validate!(user_id, device_id, command)
      when is_binary(user_id) and is_binary(device_id) and is_map(command) do
    exact_keys!(command, @keys)
    literal!(command["protocol"], "refmd.workspace-genesis-command")
    literal!(command["version"], 1)
    uuid!(command["workspace_id"])
    uuid!(command["owner_role_id"])
    non_empty!(command["name"])
    nullable_string!(command["description"])
    nullable_string!(command["icon"])

    device = Devices.get_device(device_id)

    unless match?(%{user_id: ^user_id, revoked_at: nil}, device),
      do: raise(ArgumentError, "workspace_genesis_device_invalid")

    {:ok, identity} = Encryption.user_identity_key_for_new_encryption(user_id)
    identity_signing = identity.hybrid_signing_public_key_material
    identity_encryption = identity.hybrid_encryption_public_key_material
    device_signing = device.hybrid_signing_public_key_material
    device_encryption = device.hybrid_encryption_public_key_material

    params = %{
      "workspace_id" => command["workspace_id"],
      "user_id" => user_id,
      "device_id" => device_id,
      "device_signing_key_id" => Signature.compute_signing_key_id!(device_signing),
      "device_encryption_key_id" => HybridEncryptionMaterial.compute_key_id!(device_encryption),
      "identity_signing_key_id" => Signature.compute_signing_key_id!(identity_signing),
      "identity_encryption_key_id" =>
        HybridEncryptionMaterial.compute_key_id!(identity_encryption)
    }

    envelope =
      AccountGenesisPrepare.validate_member_envelope_precommit!(
        command["workspace_member_envelope_precommit"],
        params,
        identity_encryption
      )

    %{
      command: command,
      command_hash: hash(command),
      workspace_id: command["workspace_id"],
      owner_role_id: command["owner_role_id"],
      user_id: user_id,
      device_id: device_id,
      identity_signing_material: identity_signing,
      identity_encryption_material: identity_encryption,
      device_signing_material: device_signing,
      device_encryption_material: device_encryption,
      identity_signing_key_id: params["identity_signing_key_id"],
      identity_encryption_key_id: params["identity_encryption_key_id"],
      device_signing_key_id: params["device_signing_key_id"],
      device_encryption_key_id: params["device_encryption_key_id"],
      member_envelope: envelope,
      suite_policy: Suite.current_suite_policy()
    }
  end

  def validate!(_, _, _), do: raise(ArgumentError, "workspace_genesis_command_invalid")

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp exact_keys!(value, keys) do
    unless is_map(value) and Enum.sort(Map.keys(value)) == keys,
      do: raise(ArgumentError, "workspace_genesis_command_keys_invalid")
  end

  defp literal!(actual, expected) do
    unless actual == expected, do: raise(ArgumentError, "workspace_genesis_command_invalid")
  end

  defp uuid!(value) do
    case Ecto.UUID.cast(value) do
      {:ok, ^value} -> :ok
      _ -> raise ArgumentError, "workspace_genesis_command_invalid"
    end
  end

  defp non_empty!(value) when is_binary(value) and byte_size(value) > 0, do: :ok
  defp non_empty!(_), do: raise(ArgumentError, "workspace_genesis_command_invalid")

  defp nullable_string!(nil), do: :ok
  defp nullable_string!(value) when is_binary(value), do: :ok
  defp nullable_string!(_), do: raise(ArgumentError, "workspace_genesis_command_invalid")
end
