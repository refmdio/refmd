defmodule RefMD.Encryption.KeyDirectory.AppendPolicy do
  @moduledoc false

  alias RefMD.{Devices, Encryption, Workspaces}
  alias RefMD.Encryption.KeyDirectory.State

  def validate([event], checkpoint, workspace_id, actor_user_id, pop_device_id) do
    case event do
      %{
        "payload" => %{
          "scope_kind" => "workspace",
          "scope_id" => ^workspace_id,
          "event_type" => "device_key_added",
          "actor" => %{"user_id" => ^actor_user_id, "device_id" => ^pop_device_id},
          "body" => body
        }
      } ->
        with :ok <- validate_device_key_added_body(workspace_id, body) do
          {:ok, "device"}
        end

      %{
        "payload" => %{
          "scope_kind" => "workspace",
          "scope_id" => ^workspace_id,
          "event_type" => "device_key_added",
          "actor" => %{"signer_kind" => "identity", "user_id" => ^actor_user_id},
          "body" => body
        }
      } ->
        with :ok <- validate_device_key_added_body(workspace_id, body) do
          {:ok, "device"}
        end

      %{
        "payload" =>
          %{
            "scope_kind" => "workspace",
            "scope_id" => ^workspace_id,
            "event_type" => "identity_key_added",
            "actor" => %{"user_id" => ^actor_user_id, "device_id" => ^pop_device_id},
            "body" => body
          } = payload
      } ->
        with :ok <- validate_identity_key_added_body(workspace_id, body, checkpoint, payload) do
          {:ok, "device"}
        end

      _ ->
        invalid_event()
    end
  end

  def validate(_, _, _, _, _), do: invalid_event()

  defp validate_device_key_added_body(
         workspace_id,
         %{
           "user_id" => target_user_id,
           "device_id" => device_id,
           "signing_key_id" => signing_key_id,
           "encryption_key_id" => encryption_key_id
         }
       ) do
    with role when is_binary(role) and role != "guest" <-
           Workspaces.get_member_role(workspace_id, target_user_id),
         %{user_id: ^target_user_id, revoked_at: nil} = device <- Devices.get_device(device_id),
         true <- device.signing_key_id == signing_key_id,
         true <- device.encryption_key_id == encryption_key_id do
      :ok
    else
      _ -> invalid_event()
    end
  end

  defp validate_device_key_added_body(_, _), do: invalid_event()

  defp validate_identity_key_added_body(
         workspace_id,
         %{"key_id" => key_id},
         %{"payload" => %{"identity_keys" => identity_keys}},
         event_payload
       )
       when is_list(identity_keys) do
    event_ref = State.event_ref!(event_payload)
    added_entries = identity_entries_for_event(identity_keys, event_ref)

    with [_ | _] <- added_entries,
         identity_entry when is_map(identity_entry) <- key_entry_by_id(identity_keys, key_id),
         :ok <- validate_identity_entries(workspace_id, added_entries),
         :ok <- validate_identity_entry(workspace_id, identity_entry) do
      :ok
    else
      _ -> invalid_event()
    end
  end

  defp validate_identity_key_added_body(_, _, _, _), do: invalid_event()

  defp identity_entries_for_event(identity_keys, event_ref) do
    Enum.filter(identity_keys, fn
      %{
        "valid_from" => ^event_ref,
        "key_material" => %{"owner_kind" => "identity"}
      } ->
        true

      _ ->
        false
    end)
  end

  defp validate_identity_entries(workspace_id, entries) do
    Enum.reduce_while(entries, :ok, fn entry, :ok ->
      case validate_identity_entry(workspace_id, entry) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_identity_entry(
         workspace_id,
         %{"key_id" => key_id, "key_material" => %{"owner_id" => target_user_id} = material}
       )
       when is_binary(key_id) and is_binary(target_user_id) do
    with :ok <- validate_workspace_identity_key_target(workspace_id, target_user_id),
         identity when not is_nil(identity) <-
           Encryption.get_user_identity_public_key(target_user_id),
         :ok <- validate_identity_key_material(identity, key_id, material) do
      :ok
    else
      _ -> invalid_event()
    end
  end

  defp validate_identity_entry(_, _), do: invalid_event()

  defp validate_identity_key_material(
         identity,
         key_id,
         %{
           "protocol" => "refmd.hybrid-encryption-key-material"
         } = material
       ) do
    if identity.encryption_key_id == key_id and
         identity.hybrid_encryption_public_key_material == material do
      :ok
    else
      invalid_event()
    end
  end

  defp validate_identity_key_material(
         identity,
         key_id,
         %{
           "protocol" => "refmd.hybrid-signing-key-material"
         } = material
       ) do
    if identity.signing_key_id == key_id and
         identity.hybrid_signing_public_key_material == material do
      :ok
    else
      invalid_event()
    end
  end

  defp validate_identity_key_material(_, _, _), do: invalid_event()

  defp validate_workspace_identity_key_target(workspace_id, target_user_id) do
    case Workspaces.get_member_role(workspace_id, target_user_id) do
      role when is_binary(role) and role != "guest" ->
        :ok

      _ ->
        :error
    end
  end

  defp key_entry_by_id(entries, key_id) do
    Enum.find(entries, fn
      %{"key_id" => ^key_id, "revoked_at" => nil} -> true
      %{"key_id" => ^key_id} = entry -> not Map.has_key?(entry, "revoked_at")
      _ -> false
    end)
  end

  defp invalid_event, do: {:error, :unprocessable_entity, "invalid_key_directory_event"}
end
