defmodule RefMD.Devices.Revocations.Prepare do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Signature
  alias RefMD.Devices
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Sharing.ShareLinkSecretBackupWrap

  @keys ~w(device_id revocation_mode)

  def validate!(user_id, actor_device_id, path_device_id, command)
      when is_binary(user_id) and is_binary(actor_device_id) and is_binary(path_device_id) and
             is_map(command) do
    validate_command!(path_device_id, command)

    actor = active_owned_device!(user_id, actor_device_id, "device_revocation_actor_invalid")
    target = active_owned_device!(user_id, path_device_id, "device_revocation_target_invalid")

    validate_mode_state!(user_id, target.id, command["revocation_mode"])

    key_checkpoint =
      Encryption.current_user_key_directory_checkpoint(user_id) ||
        raise(ArgumentError, "device_revocation_key_directory_missing")

    audit_bundle = Security.current_signed_audit_checkpoint!("user", user_id)
    audit_head = Security.current_verified_audit_event_head!("user:#{user_id}")
    signed_audit = audit_bundle.signed_checkpoint

    actor_signing = actor.hybrid_signing_public_key_material
    identity = Encryption.user_identity_key_for_new_encryption(user_id)
    {:ok, identity} = identity
    identity_signing = identity.hybrid_signing_public_key_material

    %{
      command: command,
      user_id: user_id,
      actor_device_id: actor_device_id,
      actor_signing_material: actor_signing,
      actor_signing_key_id: Signature.compute_signing_key_id!(actor_signing),
      target_device_id: target.id,
      target_signing_key_id: target.signing_key_id,
      target_encryption_key_id: target.encryption_key_id,
      identity_signing_material: identity_signing,
      identity_signing_key_id: Signature.compute_signing_key_id!(identity_signing),
      key_checkpoint: key_checkpoint,
      audit_head: audit_head,
      previous_signed_audit_checkpoint: signed_audit
    }
  end

  def validate!(_, _, _, _), do: raise(ArgumentError, "device_revocation_command_invalid")

  defp validate_command!(path_device_id, command) do
    unless Enum.sort(Map.keys(command)) == @keys and command["device_id"] == path_device_id and
             command["revocation_mode"] in ["security", "retire"] do
      raise ArgumentError, "device_revocation_command_invalid"
    end
  end

  defp validate_mode_state!(user_id, target_device_id, "retire") do
    if RefMD.Auth.has_unbound_sessions?(user_id),
      do: raise(ArgumentError, "retire_blocked_by_unbound_sessions")

    if Repo.exists?(
         from(wrap in ShareLinkSecretBackupWrap,
           where:
             wrap.recipient_user_id == ^user_id and
               wrap.recipient_device_id == ^target_device_id
         )
       ),
       do: raise(ArgumentError, "retire_requires_share_backup_rotation")
  end

  defp validate_mode_state!(_user_id, _target_device_id, "security"),
    do: raise(ArgumentError, "security_device_revocation_complete_set_not_implemented")

  defp active_owned_device!(user_id, device_id, error) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> device
      _ -> raise ArgumentError, error
    end
  end
end
