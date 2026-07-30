defmodule RefMD.Workspaces.AuthorityMutations.Prepare do
  @moduledoc false

  alias RefMD.Crypto.Signature
  alias RefMD.Devices.Device
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Workspaces.KekRotation
  alias RefMD.Workspaces.Members

  @command_keys %{
    "workspace.member.role_changed" => ~w(new_role_id target_user_id workspace_id),
    "workspace.member.removed" => ~w(target_user_id workspace_id),
    "workspace.kek.rotation_started" =>
      ~w(new_key_version old_key_version reason rotation_id workspace_id),
    "workspace.kek.rotation_completed" =>
      ~w(device_wrap_precommits guest_invitation_updates member_envelope_precommits new_key_version old_key_version rotation_id workspace_id workspace_invitation_updates),
    "workspace.kek.old_key_deleted" =>
      ~w(deletion_manifest device_key_deletion_proofs old_key_version rotation_id wipe_required_device_ids workspace_id)
  }

  def validate!(actor_user_id, actor_device_id, event_type, command)
      when is_binary(actor_user_id) and is_binary(actor_device_id) and is_binary(event_type) and
             is_map(command) do
    validate_command!(event_type, command)
    workspace_id = command["workspace_id"]
    actor = active_actor!(actor_user_id, actor_device_id)
    business = validate_business!(event_type, command, actor_user_id, actor_device_id)
    key_checkpoint = Encryption.current_workspace_key_directory_checkpoint(workspace_id)
    audit_bundle = Security.current_signed_audit_checkpoint!("workspace", workspace_id)
    audit_head = Security.current_verified_audit_event_head!("workspace:#{workspace_id}")

    if is_nil(key_checkpoint) or is_nil(audit_head),
      do: raise(ArgumentError, "workspace_authority_mutation_history_missing")

    %{
      event_type: event_type,
      command: command,
      workspace_id: workspace_id,
      actor_user_id: actor_user_id,
      actor_device_id: actor_device_id,
      actor_signing_material: actor.hybrid_signing_public_key_material,
      actor_signing_key_id:
        Signature.compute_signing_key_id!(actor.hybrid_signing_public_key_material),
      key_checkpoint: key_checkpoint,
      audit_head: audit_head,
      previous_signed_audit_checkpoint: audit_bundle.signed_checkpoint,
      business: business
    }
  end

  def validate!(_, _, _, _),
    do: raise(ArgumentError, "workspace_authority_mutation_command_invalid")

  defp validate_command!(event_type, command) do
    expected = Map.get(@command_keys, event_type)

    unless expected && Enum.sort(Map.keys(command)) == expected &&
             match?({:ok, _}, Ecto.UUID.cast(command["workspace_id"])) do
      raise ArgumentError, "workspace_authority_mutation_command_invalid"
    end
  end

  defp validate_business!(
         "workspace.member.role_changed",
         command,
         actor_user_id,
         _actor_device_id
       ) do
    Members.prepare_role_change!(
      command["workspace_id"],
      command["target_user_id"],
      command["new_role_id"],
      actor_user_id
    )
  end

  defp validate_business!("workspace.member.removed", command, actor_user_id, _actor_device_id) do
    Members.prepare_removal!(command["workspace_id"], command["target_user_id"], actor_user_id)
  end

  defp validate_business!(
         "workspace.kek.rotation_started",
         command,
         actor_user_id,
         _actor_device_id
       ) do
    workspace = KekRotation.prepare_start!(command["workspace_id"], actor_user_id)

    unless command["old_key_version"] == workspace.current_kek_version and
             command["new_key_version"] == workspace.current_kek_version + 1 and
             command["reason"] == "manual" and
             match?({:ok, _}, Ecto.UUID.cast(command["rotation_id"])),
           do: raise(ArgumentError, "kek_rotation_start_command_invalid")

    %{workspace: workspace}
  end

  defp validate_business!(
         "workspace.kek.rotation_completed",
         command,
         actor_user_id,
         actor_device_id
       ) do
    KekRotation.prepare_completion!(command, actor_user_id, actor_device_id)
  end

  defp validate_business!(
         "workspace.kek.old_key_deleted",
         command,
         actor_user_id,
         _actor_device_id
       ) do
    KekRotation.prepare_old_key_deletion!(command, actor_user_id)
  end

  defp active_actor!(user_id, device_id) do
    case Repo.get_by(Device, id: device_id, user_id: user_id) do
      %Device{revoked_at: nil, identity_wipe_required_at: nil} = device -> device
      _ -> raise ArgumentError, "workspace_authority_mutation_actor_invalid"
    end
  end
end
