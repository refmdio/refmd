defmodule RefMD.Sharing do
  @moduledoc """
  Public API for the Sharing context.
  """

  alias RefMD.Sharing.Access
  alias RefMD.Sharing.Bootstrap
  alias RefMD.Sharing.Management
  alias RefMD.Sharing.Mounts
  alias RefMD.Sharing.Participants
  alias RefMD.Sharing.PasswordChallenges
  alias RefMD.Sharing.Shares
  alias RefMD.Sharing.Verification.Directory

  defdelegate create_share(document, user_id, attrs), to: Shares

  defdelegate list_document_shares(document, actor_user_id, role), to: Management

  defdelegate update_share_settings(document_id, share_id, attrs), to: Management

  defdelegate delete_share(document_id, share_id), to: Management

  defdelegate delete_share(document_id, share_id, attrs), to: Management

  defdelegate update_share_exclusions(document_id, share_id, attrs), to: Management

  defdelegate update_share_keys(document_id, share_id, attrs), to: Management

  defdelegate create_share_mount(user_id, attrs), to: Mounts

  defdelegate list_share_mounts(user_id, workspace_id), to: Mounts

  defdelegate list_share_mounts_for_share(user_id, share_slug), to: Mounts

  defdelegate get_share_mount(user_id, mount_id), to: Mounts

  defdelegate get_share_mount_document_by_token(
                user_id,
                mount_id,
                document_token,
                current_rrp_device_id,
                pin_hash
              ),
              to: Mounts

  defdelegate get_share_mount_document_by_token(
                user_id,
                mount_id,
                document_token,
                current_rrp_device_id,
                pin_hash,
                session_token,
                mount_password_session
              ),
              to: Mounts

  defdelegate resolve_mounted_document_share_for_session(share_id, mount_id, document_id),
    to: Mounts

  defdelegate resolve_mounted_document_share_for_session(
                share_id,
                mount_id,
                document_id,
                requested_share_id
              ),
              to: Mounts

  defdelegate resolve_mounted_document_share_for_session(
                share_id,
                mount_id,
                document_id,
                requested_share_id,
                pin_hash
              ),
              to: Mounts

  defdelegate update_share_mount(user_id, mount_id, attrs), to: Mounts

  defdelegate delete_share_mount(user_id, mount_id), to: Mounts

  defdelegate get_share_mount_folder(
                user_id,
                mount_id,
                folder_token,
                current_rrp_device_id,
                pin_hash
              ),
              to: Mounts

  defdelegate get_share_mount_folder(
                user_id,
                mount_id,
                folder_token,
                current_rrp_device_id,
                pin_hash,
                session_token,
                mount_password_session
              ),
              to: Mounts

  defdelegate get_share_mount_challenge(user_id, mount_id), to: Mounts

  defdelegate respond_share_mount_challenge(
                user_id,
                mount_id,
                current_rrp_device_id,
                response,
                target_id,
                password_challenge_hash,
                session_token_base64 \\ nil
              ),
              to: Mounts

  defdelegate get_share_landing(share_slug, session_token_base64 \\ nil), to: Bootstrap

  defdelegate bootstrap_participant(share_slug, attrs), to: Bootstrap

  defdelegate get_password_challenge(share_slug), to: PasswordChallenges

  defdelegate password_challenge_rate_limit_share_id(share_slug), to: PasswordChallenges

  defdelegate mount_challenge_rate_limit_share_id(mount_id), to: Mounts

  defdelegate share_mount_children?(document_id), to: Mounts

  defdelegate delete_expired_password_challenges(), to: PasswordChallenges

  defdelegate respond_password_challenge(share_slug, attrs), to: PasswordChallenges

  defdelegate get_document_bootstrap(
                document_token,
                session_token_base64,
                pin_hash
              ),
              to: Bootstrap

  defdelegate get_folder_bootstrap(
                folder_token,
                session_token_base64,
                pin_hash
              ),
              to: Bootstrap

  defdelegate get_valid_participant_session_by_token_base64(token_base64), to: Participants

  defdelegate touch_participant_session(session_id), to: Participants

  defdelegate delete_participant_session(session_id), to: Participants

  defdelegate participant_session_active?(session_id), to: Participants

  defdelegate get_share_permission(share_id, document_id), to: Access

  defdelegate get_share_permission_version(share_id), to: Shares

  defdelegate share_workspace_id!(share_id), to: Shares

  defdelegate can_read_document?(share_id, document_id), to: Access

  defdelegate can_write_document?(share_id, document_id), to: Access

  defdelegate can_continue_document_session?(share_id, document_id), to: Access

  defdelegate can_join_document_session?(share_id, document_id, session_id), to: Access

  defdelegate share_session_workspace_access?(share_id, workspace_id), to: Access

  defdelegate verification_directory(share_id, document_id), to: Directory

  defdelegate document_share_participant_verification_directory(document_id),
    to: Directory

  defdelegate participant_owns_device?(principal_id, device_id), to: Participants

  defdelegate lock_participant_device_active(principal_id, device_id), to: Participants

  defdelegate participant_signing_public_material(device_id), to: Participants

  defdelegate share_participant_signer(share_id, principal_id, device_id), to: Participants

  defdelegate get_participant_device(share_id, principal_id, device_id), to: Participants

  defdelegate validate_share_participant_writer_admission(attrs), to: Participants

  defdelegate create_rrp_challenge(share_id, principal_id, device_id, session_id),
    to: Participants

  defdelegate consume_rrp_challenge(challenge, share_id, principal_id, device_id, session_id),
    to: Participants

  defdelegate generate_ws_token(session_id), to: Participants

  defdelegate verify_ws_token(token), to: Participants
end
