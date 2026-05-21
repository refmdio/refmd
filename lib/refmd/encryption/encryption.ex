defmodule RefMD.Encryption do
  @moduledoc """
  The Encryption context. Manages E2EE key storage and distribution.
  """

  alias RefMD.Encryption.{
    DocumentEncryptedKey,
    Documents,
    KeyDirectory,
    Members,
    UserEncryptedIdentityKey,
    UserEncryptedMasterKey,
    UserIdentityPublicKey,
    Users,
    WorkspaceEncryptedKey,
    WorkspaceMemberEnvelope,
    Workspaces
  }

  alias RefMD.Encryption.Wraps.ShareAuth

  # ── User Keys ──────────────────────────────────

  @spec create_user_identity_public_key(map()) ::
          {:ok, UserIdentityPublicKey.t()} | {:error, Ecto.Changeset.t()}
  defdelegate create_user_identity_public_key(attrs),
    to: Users,
    as: :create_identity_public_key

  @spec create_user_encrypted_master_key(map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, Ecto.Changeset.t()}
  defdelegate create_user_encrypted_master_key(attrs),
    to: Users,
    as: :create_encrypted_master_key

  @spec create_user_encrypted_identity_key(map()) ::
          {:ok, UserEncryptedIdentityKey.t()} | {:error, Ecto.Changeset.t()}
  defdelegate create_user_encrypted_identity_key(attrs),
    to: Users,
    as: :create_encrypted_identity_key

  @spec get_user_encrypted_master_key(Ecto.UUID.t()) :: UserEncryptedMasterKey.t() | nil
  defdelegate get_user_encrypted_master_key(user_id), to: Users, as: :get_encrypted_master_key

  @spec update_master_key_kdf(Ecto.UUID.t(), map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  defdelegate update_master_key_kdf(user_id, attrs), to: Users

  @spec update_master_key_for_password_set(Ecto.UUID.t(), map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  defdelegate update_master_key_for_password_set(user_id, attrs), to: Users

  @spec update_recovery_key(Ecto.UUID.t(), map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  defdelegate update_recovery_key(user_id, attrs), to: Users

  @spec get_user_encrypted_identity_key(Ecto.UUID.t()) :: UserEncryptedIdentityKey.t() | nil
  defdelegate get_user_encrypted_identity_key(user_id),
    to: Users,
    as: :get_encrypted_identity_key

  @spec get_user_identity_public_key(Ecto.UUID.t()) :: UserIdentityPublicKey.t() | nil
  defdelegate get_user_identity_public_key(user_id), to: Users, as: :get_identity_public_key

  # ── Workspace Keys ─────────────────────────────

  @spec create_workspace_encrypted_key_with_key_directory(map(), [map()], map()) ::
          {:ok, WorkspaceEncryptedKey.t()}
          | {:error, :invalid_sender_device | Ecto.Changeset.t() | atom()}
  defdelegate create_workspace_encrypted_key_with_key_directory(
                attrs,
                workspace_events,
                workspace_checkpoint
              ),
              to: Workspaces,
              as: :create_with_key_directory

  @spec delete_workspace_encrypted_key(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), integer()) ::
          {non_neg_integer(), nil | [term()]}
  defdelegate delete_workspace_encrypted_key(workspace_id, user_id, device_id, key_version),
    to: Workspaces,
    as: :delete

  @spec get_workspace_encrypted_keys(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: [
          WorkspaceEncryptedKey.t()
        ]
  defdelegate get_workspace_encrypted_keys(workspace_id, user_id, device_id),
    to: Workspaces,
    as: :list_for_device

  @spec user_has_active_kek?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  defdelegate user_has_active_kek?(workspace_id, user_id), to: Workspaces

  @spec get_max_active_kek_version(Ecto.UUID.t()) :: integer() | nil
  defdelegate get_max_active_kek_version(workspace_id),
    to: Workspaces,
    as: :max_active_kek_version

  # ── Member Envelopes ─────────────────────────

  @spec save_member_envelopes_with_key_directory(Ecto.UUID.t(), [map()], [map()], map()) ::
          {:ok, any()} | {:error, any()}
  defdelegate save_member_envelopes_with_key_directory(
                workspace_id,
                envelopes,
                workspace_events,
                workspace_checkpoint
              ),
              to: Members,
              as: :save_with_key_directory

  @spec get_member_envelope(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceMemberEnvelope.t() | nil
  defdelegate get_member_envelope(workspace_id, user_id), to: Members, as: :get

  @spec save_member_envelopes(Ecto.UUID.t(), [map()]) :: {:ok, any()} | {:error, any()}
  defdelegate save_member_envelopes(workspace_id, envelopes), to: Members, as: :save

  @spec validate_workspace_invitation_member_envelope(map(), map()) ::
          {:ok, %{member_envelope_hash: String.t()}} | {:error, :invalid_member_envelope}
  defdelegate validate_workspace_invitation_member_envelope(member_envelope, context),
    to: Members,
    as: :validate_invitation_member_envelope

  @spec member_has_envelope?(Ecto.UUID.t(), Ecto.UUID.t(), integer()) :: boolean()
  defdelegate member_has_envelope?(workspace_id, user_id, key_version), to: Members

  @spec all_user_devices_have_key?(Ecto.UUID.t(), Ecto.UUID.t(), integer()) :: boolean()
  defdelegate all_user_devices_have_key?(workspace_id, user_id, key_version), to: Members

  @spec all_workspace_member_devices_have_key?(Ecto.UUID.t(), integer()) :: boolean()
  defdelegate all_workspace_member_devices_have_key?(workspace_id, key_version),
    to: Members

  @spec all_members_have_envelope?(Ecto.UUID.t(), integer()) :: boolean()
  defdelegate all_members_have_envelope?(workspace_id, key_version), to: Members

  # ── Document Keys ──────────────────────────────

  @spec create_document_encrypted_key(map()) ::
          {:ok, DocumentEncryptedKey.t()} | {:error, Ecto.Changeset.t()}
  defdelegate create_document_encrypted_key(attrs), to: Documents, as: :create

  @spec get_active_document_encrypted_key(Ecto.UUID.t()) :: DocumentEncryptedKey.t() | nil
  defdelegate get_active_document_encrypted_key(document_id), to: Documents, as: :get_active

  @spec list_document_encrypted_keys(Ecto.UUID.t()) :: [DocumentEncryptedKey.t()]
  defdelegate list_document_encrypted_keys(document_id), to: Documents, as: :list

  @spec create_document_key_with_rotation(map()) ::
          {:ok, DocumentEncryptedKey.t()} | {:error, term()}
  defdelegate create_document_key_with_rotation(attrs),
    to: Documents,
    as: :create_with_rotation

  # ── Key Directory ─────────────────────────────

  @spec validate_workspace_key_directory_append(
          [map()],
          map(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, String.t()} | {:error, :unprocessable_entity, String.t()}
  defdelegate validate_workspace_key_directory_append(
                events,
                checkpoint,
                workspace_id,
                actor_user_id,
                pop_device_id
              ),
              to: KeyDirectory.AppendPolicy,
              as: :validate

  @spec append_workspace_key_directory(Ecto.UUID.t(), [map()], map(), keyword()) ::
          :ok | {:error, :invalid_key_directory}
  def append_workspace_key_directory(workspace_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.append_signed_scope("workspace", workspace_id, events, checkpoint, opts)

  @spec append_user_key_directory!(Ecto.UUID.t(), [map()], map(), keyword()) :: map()
  def append_user_key_directory!(user_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.append_signed_scope!("user", user_id, events, checkpoint, opts)

  @spec append_workspace_key_directory!(Ecto.UUID.t(), [map()], map(), keyword()) :: map()
  def append_workspace_key_directory!(workspace_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.append_signed_scope!("workspace", workspace_id, events, checkpoint, opts)

  @spec insert_initial_user_key_directory!(Ecto.UUID.t(), [map()], map(), keyword()) :: map()
  def insert_initial_user_key_directory!(user_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.insert_signed_initial_scope!("user", user_id, events, checkpoint, opts)

  @spec insert_initial_workspace_key_directory!(Ecto.UUID.t(), [map()], map(), keyword()) :: map()
  def insert_initial_workspace_key_directory!(workspace_id, events, checkpoint, opts \\ []),
    do:
      KeyDirectory.insert_signed_initial_scope!(
        "workspace",
        workspace_id,
        events,
        checkpoint,
        opts
      )

  @spec verify_user_key_directory_replay!(Ecto.UUID.t(), [map()], map(), keyword()) ::
          :ok
  def verify_user_key_directory_replay!(user_id, events, checkpoint, opts \\ []),
    do: KeyDirectory.verify_complete_replay!("user", user_id, events, checkpoint, opts)

  @spec current_user_key_directory_checkpoint(Ecto.UUID.t()) :: struct() | nil
  def current_user_key_directory_checkpoint(user_id),
    do: KeyDirectory.current_checkpoint("user", user_id)

  @spec current_workspace_key_directory_checkpoint(Ecto.UUID.t()) :: struct() | nil
  def current_workspace_key_directory_checkpoint(workspace_id),
    do: KeyDirectory.current_checkpoint("workspace", workspace_id)

  @spec current_user_key_directory_pin(Ecto.UUID.t()) :: struct() | nil
  def current_user_key_directory_pin(user_id), do: KeyDirectory.current_pin("user", user_id)

  @spec current_workspace_key_directory_pin(Ecto.UUID.t()) :: struct() | nil
  def current_workspace_key_directory_pin(workspace_id),
    do: KeyDirectory.current_pin("workspace", workspace_id)

  @spec workspace_key_directory_event_type_by_hash(Ecto.UUID.t(), binary()) :: String.t() | nil
  def workspace_key_directory_event_type_by_hash(workspace_id, event_hash) do
    case KeyDirectory.event_by_hash("workspace", workspace_id, event_hash) do
      %{event_type: event_type} -> event_type
      _ -> nil
    end
  end

  @spec workspace_key_directory_event_by_hash(Ecto.UUID.t(), binary()) :: struct() | nil
  def workspace_key_directory_event_by_hash(workspace_id, event_hash),
    do: KeyDirectory.event_by_hash("workspace", workspace_id, event_hash)

  @spec workspace_key_directory_checkpoint_covering_event_head(Ecto.UUID.t(), pos_integer()) ::
          struct() | nil
  def workspace_key_directory_checkpoint_covering_event_head(workspace_id, event_sequence),
    do: KeyDirectory.checkpoint_covering_event_head("workspace", workspace_id, event_sequence)

  @spec workspace_key_directory_checkpoints_between(Ecto.UUID.t(), pos_integer(), pos_integer()) ::
          [
            struct()
          ]
  def workspace_key_directory_checkpoints_between(workspace_id, first_sequence, last_sequence),
    do: KeyDirectory.checkpoints_between("workspace", workspace_id, first_sequence, last_sequence)

  @spec active_user_key_material_in_current_checkpoint(Ecto.UUID.t(), binary()) ::
          {:ok, map()} | {:error, :not_found}
  def active_user_key_material_in_current_checkpoint(user_id, key_id),
    do: KeyDirectory.active_key_material_in_current_checkpoint("user", user_id, key_id)

  @spec active_workspace_key_material_in_current_checkpoint(Ecto.UUID.t(), binary()) ::
          {:ok, map()} | {:error, :not_found}
  def active_workspace_key_material_in_current_checkpoint(workspace_id, key_id),
    do: KeyDirectory.active_key_material_in_current_checkpoint("workspace", workspace_id, key_id)

  @spec user_key_directory_events_after_until(Ecto.UUID.t(), non_neg_integer(), pos_integer()) ::
          [
            struct()
          ]
  def user_key_directory_events_after_until(user_id, after_sequence, head_sequence),
    do: KeyDirectory.events_after_until("user", user_id, after_sequence, head_sequence)

  @spec workspace_key_directory_events_after_until(
          Ecto.UUID.t(),
          non_neg_integer(),
          pos_integer()
        ) :: [struct()]
  def workspace_key_directory_events_after_until(workspace_id, after_sequence, head_sequence),
    do: KeyDirectory.events_after_until("workspace", workspace_id, after_sequence, head_sequence)

  @spec workspace_key_directory_events_up_to(Ecto.UUID.t(), pos_integer()) :: [struct()]
  def workspace_key_directory_events_up_to(workspace_id, head_sequence),
    do: KeyDirectory.events_up_to("workspace", workspace_id, head_sequence)

  @spec workspace_key_directory_ancestry_for_body_field(
          Ecto.UUID.t(),
          String.t(),
          String.t(),
          Ecto.UUID.t(),
          map() | nil
        ) :: %{checkpoints: [map()], events: [map()]}
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

  @spec latest_user_key_directory_delta(Ecto.UUID.t(), map()) ::
          {:ok,
           %{
             checkpoint: struct(),
             checkpoints: [struct()],
             events: [struct()],
             pin: struct() | nil
           }}
          | {:error, :not_found | :invalid_anchor}
  def latest_user_key_directory_delta(user_id, client_anchor),
    do: latest_key_directory_delta("user", user_id, client_anchor)

  @spec latest_workspace_key_directory_delta(Ecto.UUID.t(), map()) ::
          {:ok,
           %{
             checkpoint: struct(),
             checkpoints: [struct()],
             events: [struct()],
             pin: struct() | nil
           }}
          | {:error, :not_found | :invalid_anchor}
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

  # ── Workspace/Member Key Material ─────────────

  @spec create_workspace_encrypted_key_from_client_wrap(map(), map(), map(), [map()], map()) ::
          {:ok, WorkspaceEncryptedKey.t()} | {:error, term()}
  defdelegate create_workspace_encrypted_key_from_client_wrap(
                container,
                metadata,
                validation_context,
                workspace_events,
                workspace_checkpoint
              ),
              to: Workspaces,
              as: :create_from_client_wrap

  @spec validate_share_link_secret_backup_wrap(map(), map()) ::
          :ok | {:error, :invalid_share_link_secret_backup_wrap}
  defdelegate validate_share_link_secret_backup_wrap(wrap, context),
    to: Workspaces

  @spec workspace_device_key_response_fields(WorkspaceEncryptedKey.t()) :: map()
  defdelegate workspace_device_key_response_fields(key),
    to: Workspaces,
    as: :device_key_response_fields

  @spec encrypt_share_auth_key(binary(), Ecto.UUID.t()) ::
          {:ok, %{ciphertext: binary(), nonce: binary(), key_id: String.t()}} | {:error, term()}
  defdelegate encrypt_share_auth_key(auth_key, share_id), to: ShareAuth, as: :encrypt

  @spec decrypt_share_auth_key(binary(), binary(), String.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, term()}
  defdelegate decrypt_share_auth_key(ciphertext_and_tag, nonce, key_id, share_id),
    to: ShareAuth,
    as: :decrypt

  @spec workspace_key_operation_checkpoint_envelope(WorkspaceEncryptedKey.t()) :: map() | nil
  defdelegate workspace_key_operation_checkpoint_envelope(key),
    to: Workspaces,
    as: :operation_checkpoint_envelope

  @spec workspace_key_operation_checkpoint_ancestry(WorkspaceEncryptedKey.t()) :: [map()]
  defdelegate workspace_key_operation_checkpoint_ancestry(key),
    to: Workspaces,
    as: :operation_checkpoint_ancestry

  @spec workspace_key_operation_event_ancestry(WorkspaceEncryptedKey.t()) :: [map()]
  defdelegate workspace_key_operation_event_ancestry(key),
    to: Workspaces,
    as: :operation_event_ancestry

  @spec prepare_workspace_member_envelope_from_client(map(), map(), map(), map(), map()) ::
          {:ok, map()} | {:error, :invalid_workspace_member_kek_wrap}
  defdelegate prepare_workspace_member_envelope_from_client(
                container,
                metadata,
                validation_context,
                event,
                workspace_checkpoint
              ),
              to: Members,
              as: :prepare_client_envelope

  @spec member_envelope_response_fields(WorkspaceMemberEnvelope.t()) :: map()
  defdelegate member_envelope_response_fields(envelope),
    to: Members,
    as: :response_fields

  @spec member_envelope_operation_checkpoint_envelope(WorkspaceMemberEnvelope.t()) :: map() | nil
  defdelegate member_envelope_operation_checkpoint_envelope(envelope),
    to: Members,
    as: :operation_checkpoint_envelope

  # ── Login Keys Response ────────────────────────

  @spec get_login_keys(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: map()
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
