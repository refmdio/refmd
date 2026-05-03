defmodule RefMD.Sharing do
  @moduledoc """
  Public facade for the Sharing context.
  """

  alias RefMD.Documents.Document
  alias RefMD.Sharing.Access
  alias RefMD.Sharing.Bootstrap
  alias RefMD.Sharing.Management
  alias RefMD.Sharing.Mounts
  alias RefMD.Sharing.Participants
  alias RefMD.Sharing.PasswordChallenges
  alias RefMD.Sharing.ShareParticipantDevice
  alias RefMD.Sharing.ShareParticipantSession
  alias RefMD.Sharing.Shares
  alias RefMD.Sharing.VerificationDirectories

  @type create_share_result :: Shares.create_share_result()

  @spec create_share(Document.t(), Ecto.UUID.t(), map()) :: create_share_result()
  defdelegate create_share(document, user_id, attrs), to: Shares

  @spec list_document_shares(Document.t(), Ecto.UUID.t(), %{base_role: String.t()}) :: [map()]
  defdelegate list_document_shares(document, actor_user_id, role), to: Management

  @spec update_share_settings(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), map()) ::
          {:ok,
           %{
             id: Ecto.UUID.t(),
             expires_at: DateTime.t() | nil,
             access_limit: pos_integer() | nil,
             access_count: non_neg_integer()
           }}
          | {:error, term()}
  defdelegate update_share_settings(document_id, share_id, manage_token, attrs), to: Management

  @spec delete_share(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) :: :ok | {:error, term()}
  defdelegate delete_share(document_id, share_id, manage_token), to: Management

  @spec delete_share(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  defdelegate delete_share(document_id, share_id), to: Management

  @spec update_share_exclusions(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), map()) ::
          {:ok, %{share_id: Ecto.UUID.t(), exclusions: [Ecto.UUID.t()]}} | {:error, term()}
  defdelegate update_share_exclusions(document_id, share_id, manage_token, attrs), to: Management

  @spec update_share_keys(Ecto.UUID.t(), Ecto.UUID.t(), String.t(), map()) ::
          {:ok, %{share_id: Ecto.UUID.t(), added: [Ecto.UUID.t()], replaced: [Ecto.UUID.t()]}}
          | {:error, term()}
  defdelegate update_share_keys(document_id, share_id, manage_token, attrs), to: Management

  @spec create_share_mount(Ecto.UUID.t(), map()) :: {:ok, map()} | {:error, term()}
  defdelegate create_share_mount(user_id, attrs), to: Mounts

  @spec list_share_mounts_for_share(Ecto.UUID.t(), String.t()) ::
          {:ok, %{mounts: [map()]}} | {:error, term()}
  defdelegate list_share_mounts_for_share(user_id, share_slug), to: Mounts

  @spec list_share_mounts(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, %{mounts: [map()]}} | {:error, term()}
  defdelegate list_share_mounts(user_id, workspace_id), to: Mounts

  @spec get_share_mount(Ecto.UUID.t(), Ecto.UUID.t()) :: {:ok, map()} | {:error, term()}
  defdelegate get_share_mount(user_id, mount_id), to: Mounts

  @spec get_share_mount_document(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, map()} | {:error, term()}
  defdelegate get_share_mount_document(user_id, mount_id, document_id), to: Mounts

  @spec get_share_mount_share(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, map()} | {:error, term()}
  defdelegate get_share_mount_share(user_id, mount_id, share_id), to: Mounts

  @spec resolve_mounted_document_share(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Ecto.UUID.t()} | {:error, term()}
  defdelegate resolve_mounted_document_share(user_id, mount_id, document_id), to: Mounts

  @spec update_share_mount(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, map()} | {:error, term()}
  defdelegate update_share_mount(user_id, mount_id, attrs), to: Mounts

  @spec delete_share_mount(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  defdelegate delete_share_mount(user_id, mount_id), to: Mounts

  @spec get_share_mount_folder(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) ::
          {:ok, map()} | {:error, term()}
  defdelegate get_share_mount_folder(user_id, mount_id, folder_token), to: Mounts

  @spec get_share_mount_challenge(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, %{challenge: binary(), salt: binary(), kdf_params: map()}} | {:error, term()}
  defdelegate get_share_mount_challenge(user_id, mount_id), to: Mounts

  @spec respond_share_mount_challenge(Ecto.UUID.t(), Ecto.UUID.t(), binary()) ::
          {:ok, map()} | {:error, term()}
  defdelegate respond_share_mount_challenge(user_id, mount_id, response), to: Mounts

  @spec respond_share_mount_challenge(Ecto.UUID.t(), Ecto.UUID.t(), binary(), Ecto.UUID.t() | nil) ::
          {:ok, map()} | {:error, term()}
  defdelegate respond_share_mount_challenge(user_id, mount_id, response, target_id),
    to: Mounts

  @spec get_share_landing(String.t()) ::
          {:ok, %{share: RefMD.Sharing.Share.t(), root: map()}}
          | {:error, :not_found | :invalid_slug}
  defdelegate get_share_landing(share_slug), to: Bootstrap

  @spec bootstrap_participant(String.t(), map()) ::
          {:ok,
           %{
             root: map(),
             participant: %{
               principal_id: Ecto.UUID.t(),
               device_id: Ecto.UUID.t(),
               grant: String.t()
             },
             session_token: binary()
           }}
          | {:error, term()}
  defdelegate bootstrap_participant(share_slug, attrs), to: Bootstrap

  @spec get_password_challenge(String.t()) ::
          {:ok, %{challenge: binary(), salt: binary(), kdf_params: map()}} | {:error, term()}
  defdelegate get_password_challenge(share_slug), to: PasswordChallenges

  @spec delete_expired_password_challenges() :: {non_neg_integer(), nil}
  defdelegate delete_expired_password_challenges(), to: PasswordChallenges

  @spec respond_password_challenge(String.t(), map()) ::
          {:ok,
           %{
             root: map(),
             participant: %{
               principal_id: Ecto.UUID.t(),
               device_id: Ecto.UUID.t(),
               grant: String.t()
             },
             session_token: binary()
           }}
          | {:error, term()}
  defdelegate respond_password_challenge(share_slug, attrs), to: PasswordChallenges

  @spec get_document_bootstrap(String.t(), String.t() | nil) ::
          {:ok, map()} | {:error, :not_found}
  defdelegate get_document_bootstrap(document_token, session_token_base64), to: Bootstrap

  @spec get_folder_bootstrap(String.t(), String.t() | nil) :: {:ok, map()} | {:error, :not_found}
  defdelegate get_folder_bootstrap(folder_token, session_token_base64), to: Bootstrap

  @spec get_valid_participant_session_by_token_base64(String.t() | nil) ::
          {:ok, ShareParticipantSession.t()} | {:error, :invalid_session | :invalid_token}
  defdelegate get_valid_participant_session_by_token_base64(token_base64), to: Participants

  @spec touch_participant_session(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  defdelegate touch_participant_session(session_id), to: Participants

  @spec delete_participant_session(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  defdelegate delete_participant_session(session_id), to: Participants

  @spec participant_session_active?(Ecto.UUID.t()) :: boolean()
  defdelegate participant_session_active?(session_id), to: Participants

  @spec get_share_permission(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, String.t()} | {:error, :not_found}
  defdelegate get_share_permission(share_id, document_id), to: Access

  @spec can_read_document?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  defdelegate can_read_document?(share_id, document_id), to: Access

  @spec can_write_document?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  defdelegate can_write_document?(share_id, document_id), to: Access

  @spec can_continue_document_session?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  defdelegate can_continue_document_session?(share_id, document_id), to: Access

  @spec can_join_document_session?(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  defdelegate can_join_document_session?(share_id, document_id, session_id), to: Access

  @spec verification_directory(Ecto.UUID.t(), Ecto.UUID.t()) :: map()
  defdelegate verification_directory(share_id, document_id), to: VerificationDirectories

  @spec document_share_participant_verification_directory(Ecto.UUID.t()) :: map()
  defdelegate document_share_participant_verification_directory(document_id),
    to: VerificationDirectories

  @spec participant_owns_device?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  defdelegate participant_owns_device?(principal_id, device_id), to: Participants

  @spec get_participant_device(Ecto.UUID.t()) :: ShareParticipantDevice.t() | nil
  defdelegate get_participant_device(device_id), to: Participants

  @spec create_pop_challenge(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, Ecto.Changeset.t()}
  defdelegate create_pop_challenge(share_id, device_id), to: Participants

  @spec consume_pop_challenge(binary(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, :invalid_challenge}
  defdelegate consume_pop_challenge(challenge, share_id, device_id), to: Participants

  @spec generate_ws_token(Ecto.UUID.t()) :: String.t()
  defdelegate generate_ws_token(session_id), to: Participants

  @spec verify_ws_token(String.t()) ::
          {:ok, Ecto.UUID.t(), ShareParticipantSession.t()} | {:error, atom()}
  defdelegate verify_ws_token(token), to: Participants
end
