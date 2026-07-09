defmodule RefMD.Encryption do
  @moduledoc """
  The Encryption context. Manages E2EE key storage and distribution.
  """

  alias RefMD.Encryption.{
    Documents,
    KeyDirectory,
    Members,
    Users,
    Workspaces
  }

  alias RefMD.Encryption.Wraps.{ShareAuth, SignedPQ}

  defdelegate create_user_identity_public_key(attrs),
    to: Users,
    as: :create_identity_public_key

  defdelegate create_user_encrypted_master_key(attrs),
    to: Users,
    as: :create_encrypted_master_key

  defdelegate create_user_encrypted_identity_key(attrs),
    to: Users,
    as: :create_encrypted_identity_key

  defdelegate get_user_encrypted_master_key(user_id), to: Users, as: :get_encrypted_master_key

  defdelegate update_master_key_kdf(user_id, attrs), to: Users

  defdelegate update_master_key_for_password_set(user_id, attrs), to: Users

  defdelegate update_recovery_key(user_id, attrs), to: Users

  defdelegate get_user_encrypted_identity_key(user_id),
    to: Users,
    as: :get_encrypted_identity_key

  defdelegate get_user_identity_public_key(user_id), to: Users, as: :get_identity_public_key

  defdelegate create_workspace_encrypted_key_with_key_directory(
                attrs,
                workspace_events,
                workspace_checkpoint
              ),
              to: Workspaces,
              as: :create_with_key_directory

  defdelegate delete_workspace_encrypted_key(workspace_id, user_id, device_id, key_version),
    to: Workspaces,
    as: :delete

  defdelegate get_workspace_encrypted_keys(workspace_id, user_id, device_id),
    to: Workspaces,
    as: :list_for_device

  defdelegate user_has_active_kek?(workspace_id, user_id), to: Workspaces

  defdelegate get_max_active_kek_version(workspace_id),
    to: Workspaces,
    as: :max_active_kek_version

  defdelegate save_member_envelopes_with_key_directory(
                workspace_id,
                envelopes,
                workspace_events,
                workspace_checkpoint
              ),
              to: Members,
              as: :save_with_key_directory

  defdelegate get_member_envelope(workspace_id, user_id), to: Members, as: :get

  defdelegate save_member_envelopes(workspace_id, envelopes), to: Members, as: :save

  defdelegate validate_workspace_invitation_member_envelope(member_envelope, context),
    to: Members,
    as: :validate_invitation_member_envelope

  defdelegate member_has_envelope?(workspace_id, user_id, key_version), to: Members

  defdelegate all_user_devices_have_key?(workspace_id, user_id, key_version), to: Members

  defdelegate all_workspace_member_devices_have_key?(workspace_id, key_version),
    to: Members

  defdelegate all_members_have_envelope?(workspace_id, key_version), to: Members

  defdelegate create_document_encrypted_key(attrs), to: Documents, as: :create

  defdelegate get_active_document_encrypted_key(document_id), to: Documents, as: :get_active

  defdelegate list_document_encrypted_keys(document_id), to: Documents, as: :list

  defdelegate create_document_key_with_rotation(attrs),
    to: Documents,
    as: :create_with_rotation

  defdelegate validate_workspace_key_directory_append(
                events,
                checkpoint,
                workspace_id,
                actor_user_id,
                rrp_device_id
              ),
              to: KeyDirectory.AppendPolicy,
              as: :validate

  def append_workspace_key_directory(workspace_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.append_signed_scope("workspace", workspace_id, events, checkpoint, opts)

  def append_user_key_directory!(user_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.append_signed_scope!("user", user_id, events, checkpoint, opts)

  def append_workspace_key_directory!(workspace_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.append_signed_scope!("workspace", workspace_id, events, checkpoint, opts)

  def insert_initial_user_key_directory!(user_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.insert_signed_initial_scope!("user", user_id, events, checkpoint, opts)

  def insert_initial_workspace_key_directory!(workspace_id, events, checkpoint, opts \\ []),
    do:
      KeyDirectory.insert_signed_initial_scope!(
        "workspace",
        workspace_id,
        events,
        checkpoint,
        opts
      )

  def verify_user_key_directory_replay!(user_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.verify_complete_replay!("user", user_id, events, checkpoint, opts)

  def current_user_key_directory_checkpoint(user_id),
    do: KeyDirectory.current_checkpoint("user", user_id)

  def current_workspace_key_directory_checkpoint(workspace_id),
    do: KeyDirectory.current_checkpoint("workspace", workspace_id)

  def current_user_key_directory_pin(user_id), do: KeyDirectory.current_pin("user", user_id)

  def user_key_directory_checkpoints_between(user_id, first_sequence, last_sequence),
    do: KeyDirectory.checkpoints_between("user", user_id, first_sequence, last_sequence)

  def current_workspace_key_directory_pin(workspace_id),
    do: KeyDirectory.current_pin("workspace", workspace_id)

  def workspace_key_directory_event_type_by_hash(workspace_id, event_hash) do
    case KeyDirectory.event_by_hash("workspace", workspace_id, event_hash) do
      %{event_type: event_type} -> event_type
      _ -> nil
    end
  end

  def workspace_key_directory_event_by_hash(workspace_id, event_hash),
    do: KeyDirectory.event_by_hash("workspace", workspace_id, event_hash)

  def workspace_key_directory_checkpoint_covering_event_head(workspace_id, event_sequence),
    do: KeyDirectory.checkpoint_covering_event_head("workspace", workspace_id, event_sequence)

  def workspace_key_directory_checkpoints_between(workspace_id, first_sequence, last_sequence),
    do: KeyDirectory.checkpoints_between("workspace", workspace_id, first_sequence, last_sequence)

  def active_user_key_material_in_current_checkpoint(user_id, key_id),
    do: KeyDirectory.active_key_material_in_current_checkpoint("user", user_id, key_id)

  def active_workspace_key_material_in_current_checkpoint(workspace_id, key_id),
    do: KeyDirectory.active_key_material_in_current_checkpoint("workspace", workspace_id, key_id)

  def user_key_directory_events_after_until(user_id, after_sequence, head_sequence),
    do: KeyDirectory.events_after_until("user", user_id, after_sequence, head_sequence)

  def workspace_key_directory_events_after_until(workspace_id, after_sequence, head_sequence),
    do: KeyDirectory.events_after_until("workspace", workspace_id, after_sequence, head_sequence)

  def workspace_key_directory_events_up_to(workspace_id, head_sequence),
    do: KeyDirectory.events_up_to("workspace", workspace_id, head_sequence)

  def workspace_key_directory_ancestry_for_body_field(
        workspace_id,
        created_event_type,
        body_key,
        body_value,
        current_checkpoint
      ) do
    with %{sequence: _} <- current_checkpoint,
         %{sequence: created_sequence} <-
           KeyDirectory.event_by_body_field(
             "workspace",
             workspace_id,
             created_event_type,
             body_key,
             body_value
           ),
         %{sequence: bootstrap_sequence, covered_event_head_sequence: bootstrap_head_sequence} <-
           KeyDirectory.checkpoint_covering_event_head(
             "workspace",
             workspace_id,
             created_sequence - 1
           ) do
      %{
        checkpoints:
          KeyDirectory.checkpoints_between(
            "workspace",
            workspace_id,
            bootstrap_sequence,
            current_checkpoint.sequence - 1
          ),
        events:
          workspace_key_directory_events_after_until(
            workspace_id,
            bootstrap_head_sequence,
            current_checkpoint.covered_event_head_sequence
          )
      }
    else
      _ -> %{checkpoints: [], events: []}
    end
  end

  def latest_user_key_directory_delta(user_id, client_anchor),
    do: latest_key_directory_delta("user", user_id, client_anchor)

  def latest_workspace_key_directory_delta(workspace_id, client_anchor),
    do: latest_key_directory_delta("workspace", workspace_id, client_anchor)

  defp latest_key_directory_delta(scope_kind, scope_id, client_anchor) do
    case KeyDirectory.current_checkpoint(scope_kind, scope_id) do
      nil ->
        {:error, :not_found}

      checkpoint ->
        with :ok <- assert_client_anchor(scope_kind, scope_id, client_anchor, checkpoint) do
          events =
            KeyDirectory.events_after_until(
              scope_kind,
              scope_id,
              client_anchor.event_head_sequence,
              checkpoint.covered_event_head_sequence
            )
            |> assert_stored_events!()

          checkpoints =
            KeyDirectory.checkpoints_between(
              scope_kind,
              scope_id,
              client_anchor.checkpoint_sequence,
              checkpoint.sequence - 1
            )
            |> assert_stored_checkpoints!()

          {:ok,
           %{
             checkpoint: checkpoint,
             checkpoints: checkpoints,
             events: events,
             pin: KeyDirectory.current_pin(scope_kind, scope_id)
           }}
        end
    end
  end

  defp assert_stored_events!(events) do
    Enum.each(events, &KeyDirectory.assert_stored_event!/1)
    events
  end

  defp assert_stored_checkpoints!(checkpoints) do
    Enum.each(checkpoints, &KeyDirectory.assert_stored_checkpoint!/1)
    checkpoints
  end

  defp assert_client_anchor(scope_kind, scope_id, client_anchor, server_checkpoint) do
    cond do
      client_anchor.checkpoint_sequence > server_checkpoint.sequence ->
        {:error, :invalid_anchor}

      client_anchor.event_head_sequence > server_checkpoint.covered_event_head_sequence ->
        {:error, :invalid_anchor}

      true ->
        case KeyDirectory.checkpoints_between(
               scope_kind,
               scope_id,
               client_anchor.checkpoint_sequence,
               client_anchor.checkpoint_sequence
             ) do
          [
            %{
              checkpoint_hash: checkpoint_hash,
              covered_event_head_sequence: event_head_sequence,
              covered_event_head_hash: event_head_hash
            }
          ]
          when checkpoint_hash == client_anchor.checkpoint_hash and
                 event_head_sequence == client_anchor.event_head_sequence and
                 event_head_hash == client_anchor.event_head_hash ->
            :ok

          _ ->
            {:error, :invalid_anchor}
        end
    end
  end

  defdelegate create_workspace_encrypted_key_from_client_wrap(
                container,
                metadata,
                validation_context,
                workspace_events,
                workspace_checkpoint
              ),
              to: Workspaces,
              as: :create_from_client_wrap

  defdelegate validate_share_link_secret_backup_wrap(wrap, context),
    to: Workspaces

  defdelegate workspace_device_key_response_fields(key),
    to: SignedPQ,
    as: :response_fields

  defdelegate encrypt_share_auth_key(auth_key, share_id), to: ShareAuth, as: :encrypt

  defdelegate decrypt_share_auth_key(ciphertext_and_tag, nonce, key_id, share_id),
    to: ShareAuth,
    as: :decrypt

  defdelegate workspace_key_operation_checkpoint_envelope(key),
    to: Workspaces,
    as: :operation_checkpoint_envelope

  defdelegate workspace_key_operation_checkpoint_ancestry(key),
    to: Workspaces,
    as: :operation_checkpoint_ancestry

  defdelegate workspace_key_operation_event_ancestry(key),
    to: Workspaces,
    as: :operation_event_ancestry

  defdelegate prepare_workspace_member_envelope_from_client(
                container,
                metadata,
                validation_context,
                event,
                workspace_checkpoint
              ),
              to: Members,
              as: :prepare_client_envelope

  defdelegate member_envelope_response_fields(envelope),
    to: SignedPQ,
    as: :response_fields

  defdelegate member_envelope_operation_checkpoint_envelope(envelope),
    to: Members,
    as: :operation_checkpoint_envelope

  def get_login_keys(user_id, device_id) do
    %{
      encrypted_master_key: get_user_encrypted_master_key(user_id),
      encrypted_identity_key: get_user_encrypted_identity_key(user_id),
      identity_public_key: get_user_identity_public_key(user_id),
      device_encrypted_umk:
        if(device_id, do: RefMD.Devices.get_device_encrypted_umk(user_id, device_id))
    }
  end
end
