defmodule RefMDWeb.Http.PopTranscript do
  @moduledoc false

  alias RefMD.Crypto.Signature
  alias RefMD.Encryption
  alias RefMD.Workspaces

  def user_actor!(device, user_id) when is_map(device) do
    if Workspaces.guest_user?(user_id) do
      case Workspaces.active_guest_device_workspace_id(user_id, Map.fetch!(device, :id)) do
        {:ok, workspace_id} -> guest_user_actor!(device, user_id, workspace_id)
        {:error, :not_found} -> workspace_user_actor!(device, user_id)
      end
    else
      workspace_user_actor!(device, user_id)
    end
  end

  defp workspace_user_actor!(device, user_id) when is_map(device) do
    device_id = Map.fetch!(device, :id)
    signing_key_id = Map.fetch!(device, :signing_key_id)
    checkpoint = assert_user_actor_active!(device, user_id)

    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "user",
      "key_scope_id" => user_id,
      "key_checkpoint_sequence" => required_integer!(checkpoint.sequence),
      "key_checkpoint_hash" => required_string!(checkpoint.checkpoint_hash)
    }
  end

  defp guest_user_actor!(device, user_id, workspace_id) when is_map(device) do
    device_id = Map.fetch!(device, :id)
    signing_key_id = Map.fetch!(device, :signing_key_id)
    checkpoint = assert_guest_user_actor_active!(device, workspace_id)

    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => required_integer!(checkpoint.sequence),
      "key_checkpoint_hash" => required_string!(checkpoint.checkpoint_hash)
    }
  end

  def share_participant_actor!(device, share_id, workspace_id) when is_map(device) do
    device_id = Map.fetch!(device, :id)
    principal_id = Map.fetch!(device, :principal_id)
    signing_key_id = Map.fetch!(device, :signing_key_id)
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(workspace_id)
    assert_share_participant_actor_active!(device, workspace_id, checkpoint)

    %{
      "signer_kind" => "share_participant_device",
      "share_id" => share_id,
      "share_participant_principal_id" => principal_id,
      "share_participant_device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => required_integer!(checkpoint && checkpoint.sequence),
      "key_checkpoint_hash" => required_string!(checkpoint && checkpoint.checkpoint_hash)
    }
  end

  def assert_user_actor_active!(device, user_id) when is_map(device) do
    device_id = Map.fetch!(device, :id)
    signing_key_id = Map.fetch!(device, :signing_key_id)
    signing_material = Map.fetch!(device, :hybrid_signing_public_key_material)
    checkpoint = Encryption.current_user_key_directory_checkpoint(user_id)

    with true <- not is_nil(checkpoint),
         {:ok, key_material} <-
           Encryption.active_user_key_material_in_current_checkpoint(
             user_id,
             signing_key_id
           ),
         true <- key_material == signing_material,
         true <- key_material["owner_kind"] == "device",
         true <- key_material["owner_id"] == device_id do
      checkpoint
    else
      _ -> raise(ArgumentError, "pop_actor_key_directory_inactive")
    end
  end

  def assert_guest_user_actor_active!(device, workspace_id) when is_map(device) do
    device_id = Map.fetch!(device, :id)
    signing_key_id = Map.fetch!(device, :signing_key_id)
    signing_material = Map.fetch!(device, :hybrid_signing_public_key_material)
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(workspace_id)

    with true <- not is_nil(checkpoint),
         {:ok, key_material} <-
           Encryption.active_workspace_key_material_in_current_checkpoint(
             workspace_id,
             signing_key_id
           ),
         true <- key_material == signing_material,
         true <- key_material["owner_kind"] == "device",
         true <- key_material["owner_id"] == device_id do
      checkpoint
    else
      _ -> raise(ArgumentError, "pop_actor_key_directory_inactive")
    end
  end

  def assert_share_participant_actor_active!(device, workspace_id, checkpoint)
      when is_map(device) do
    device_id = Map.fetch!(device, :id)
    signing_key_id = Map.fetch!(device, :signing_key_id)
    signing_material = Map.fetch!(device, :hybrid_signing_public_key_material)

    with true <- not is_nil(checkpoint),
         true <- is_nil(Map.get(device, :revoked_at)),
         true <-
           Signature.compute_signing_key_id!(signing_material) == signing_key_id,
         true <-
           signing_material["owner_kind"] == "share_participant_device",
         true <- signing_material["owner_id"] == device_id,
         true <- is_binary(signing_key_id),
         true <- is_binary(workspace_id) do
      :ok
    else
      _ -> raise(ArgumentError, "pop_actor_key_directory_inactive")
    end
  end

  defp required_integer!(value) when is_integer(value) and value > 0, do: value
  defp required_integer!(_), do: raise(ArgumentError, "pop_actor_checkpoint_sequence_invalid")

  defp required_string!(value) when is_binary(value) and value != "", do: value
  defp required_string!(_), do: raise(ArgumentError, "pop_actor_checkpoint_hash_invalid")
end
