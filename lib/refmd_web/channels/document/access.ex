defmodule RefMDWeb.Channels.Document.Access do
  @moduledoc false

  alias RefMD.Devices
  alias RefMD.Sharing
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC

  @spec check_ephemeral(Phoenix.Socket.t()) :: :ok | {:error, String.t()}
  def check_ephemeral(socket) do
    if share_context?(socket) do
      if is_nil(socket.assigns.document.archived_at) and
           Sharing.can_write_document?(
             socket.assigns.current_share_id,
             socket.assigns.document.id
           ) do
        :ok
      else
        {:error, "permission_denied"}
      end
    else
      case check_broadcast(socket) do
        :ok -> :ok
        :evict -> {:error, "permission_denied"}
        :skip -> {:error, "permission_check_failed"}
      end
    end
  end

  @spec check_broadcast(Phoenix.Socket.t()) :: :ok | :evict | :skip
  def check_broadcast(socket) do
    if share_context?(socket) do
      share_read_access_result(socket)
    else
      try do
        workspace_read_access_result(
          socket.assigns.document,
          socket.assigns.current_user_id
        )
      rescue
        _ -> :skip
      end
    end
  end

  @spec check_join(map(), Ecto.UUID.t(), Phoenix.Socket.t(), Ecto.UUID.t() | nil) ::
          :ok | {:error, %{reason: String.t()}}
  def check_join(document, user_id, socket, mounted_share_id) do
    if socket.assigns[:session_kind] == :share_participant do
      if Workspaces.share_links_enabled?(document.workspace_id) and
           Sharing.can_join_document_session?(
             socket.assigns.current_share_id,
             document.id,
             socket.assigns.current_session.id
           ) do
        :ok
      else
        {:error, %{reason: "permission_denied"}}
      end
    else
      if is_binary(mounted_share_id) do
        :ok
      else
        check_workspace_read(document.workspace_id, user_id, document)
      end
    end
  end

  @spec resolve_mounted_share_id(map(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, Ecto.UUID.t() | nil} | {:error, %{reason: String.t()}}
  def resolve_mounted_share_id(%{"mount_id" => mount_id}, user_id, document_id)
      when is_binary(mount_id) do
    case Sharing.resolve_mounted_document_share(user_id, mount_id, document_id) do
      {:ok, share_id} -> {:ok, share_id}
      {:error, _reason} -> {:error, %{reason: "permission_denied"}}
    end
  end

  def resolve_mounted_share_id(_params, _user_id, _document_id), do: {:ok, nil}

  @spec share_session_still_authorized?(Phoenix.Socket.t()) :: boolean()
  def share_session_still_authorized?(socket) do
    Workspaces.share_links_enabled?(socket.assigns.document.workspace_id) and
      Sharing.participant_session_active?(socket.assigns.current_session.id) and
      Sharing.participant_owns_device?(
        socket.assigns.share_participant_principal_id,
        socket.assigns.device_id
      ) and
      Sharing.can_continue_document_session?(
        socket.assigns.current_share_id,
        socket.assigns.document_id
      )
  end

  @spec mounted_share_still_authorized?(Phoenix.Socket.t()) :: boolean()
  def mounted_share_still_authorized?(socket) do
    case Sharing.resolve_mounted_document_share(
           socket.assigns.current_user_id,
           socket.assigns.mount_id,
           socket.assigns.document_id
         ) do
      {:ok, share_id} ->
        share_id == socket.assigns.current_share_id and
          Workspaces.share_links_enabled?(socket.assigns.document.workspace_id)

      _ ->
        false
    end
  end

  @spec subscribe_device_revocation(Phoenix.Socket.t()) :: :ok
  def subscribe_device_revocation(%{
        assigns: %{session_kind: :share_participant, current_session: %{device_id: device_id}}
      })
      when is_binary(device_id) do
    Phoenix.PubSub.subscribe(RefMD.PubSub, "share_device_revocation:#{device_id}")
    :ok
  end

  def subscribe_device_revocation(%{assigns: %{session_kind: :share_participant}}), do: :ok

  def subscribe_device_revocation(%{assigns: %{current_user_id: user_id}}) do
    Phoenix.PubSub.subscribe(RefMD.PubSub, "device_revocation:#{user_id}")
    :ok
  end

  @spec maybe_subscribe_share_document_revocation(Ecto.UUID.t() | nil, Ecto.UUID.t()) :: :ok
  def maybe_subscribe_share_document_revocation(share_id, document_id)
      when is_binary(share_id) and is_binary(document_id) do
    Phoenix.PubSub.subscribe(RefMD.PubSub, "share_document_revocation:#{share_id}:#{document_id}")
    :ok
  end

  def maybe_subscribe_share_document_revocation(_share_id, _document_id), do: :ok

  @spec validate_write(Phoenix.Socket.t()) :: :ok | {:error, String.t()}
  def validate_write(socket) do
    cond do
      socket.assigns[:session_kind] == :share_participant ->
        validate_share_write_access(socket)

      is_binary(socket.assigns[:mounted_share_id]) ->
        validate_mounted_share_write_access(socket)

      true ->
        validate_workspace_write_access(socket)
    end
  end

  @spec publication_sync_allowed?(
          map(),
          Ecto.UUID.t(),
          Phoenix.Socket.t() | nil,
          Ecto.UUID.t() | nil
        ) :: boolean()
  def publication_sync_allowed?(document, user_id, socket, mounted_share_id) do
    cond do
      share_participant_socket?(socket) ->
        false

      is_binary(mounted_share_id) ->
        false

      Workspaces.guest_user?(user_id) ->
        false

      true ->
        case Workspaces.get_member_with_role(document.workspace_id, user_id) do
          {_member, role} -> role_allows_document_write?(role)
          nil -> false
        end
    end
  end

  @spec validate_device_active(Phoenix.Socket.t()) :: :ok | {:error, String.t()}
  def validate_device_active(socket) do
    if socket.assigns[:session_kind] == :share_participant do
      if Sharing.participant_owns_device?(
           socket.assigns.share_participant_principal_id,
           socket.assigns.device_id
         ) do
        :ok
      else
        {:error, "device_revoked"}
      end
    else
      case Devices.get_device(socket.assigns.device_id) do
        %{user_id: uid, revoked_at: nil} when uid == socket.assigns.current_user_id ->
          :ok

        _ ->
          {:error, "device_revoked"}
      end
    end
  end

  defp share_context?(socket) do
    socket.assigns[:session_kind] == :share_participant or
      is_binary(socket.assigns[:mounted_share_id])
  end

  defp share_participant_socket?(%{assigns: %{session_kind: :share_participant}}), do: true
  defp share_participant_socket?(_socket), do: false

  defp check_workspace_read(workspace_id, user_id, document) do
    if Workspaces.guest_user?(user_id) do
      guest_read_access(workspace_id, user_id, document)
    else
      member_read_access(workspace_id, user_id)
    end
  end

  defp share_read_access_result(socket) do
    if Sharing.can_read_document?(socket.assigns.current_share_id, socket.assigns.document.id) do
      :ok
    else
      :evict
    end
  end

  defp workspace_read_access_result(document, user_id) do
    if Workspaces.guest_user?(user_id) do
      case guest_read_access(document.workspace_id, user_id, document) do
        :ok -> :ok
        {:error, _reason} -> :evict
      end
    else
      case member_read_access(document.workspace_id, user_id) do
        :ok -> :ok
        {:error, _reason} -> :evict
      end
    end
  end

  defp guest_read_access(workspace_id, user_id, document) do
    case Workspaces.authorize_guest_permission(workspace_id, user_id, "document:read", document) do
      :ok -> :ok
      {:error, _reason} -> {:error, %{reason: "permission_denied"}}
    end
  end

  defp member_read_access(workspace_id, user_id) do
    case Workspaces.get_member_with_role(workspace_id, user_id) do
      nil ->
        {:error, %{reason: "not_a_member"}}

      {_member, role} ->
        if role_allows_document_read?(role) do
          :ok
        else
          {:error, %{reason: "permission_denied"}}
        end
    end
  end

  defp role_allows_document_read?(role) do
    role
    |> RequireRBAC.effective_permissions()
    |> MapSet.member?("document:read")
  end

  defp role_allows_document_write?(role) do
    role
    |> RequireRBAC.effective_permissions()
    |> MapSet.member?("document:write")
  end

  defp validate_share_write_access(socket) do
    if socket.assigns.share_participant_grant == "edit" and
         Workspaces.share_links_enabled?(socket.assigns.document.workspace_id) and
         Sharing.can_write_document?(socket.assigns.current_share_id, socket.assigns.document.id) do
      :ok
    else
      {:error, "permission_denied"}
    end
  end

  defp validate_mounted_share_write_access(socket) do
    if Workspaces.share_links_enabled?(socket.assigns.document.workspace_id) and
         Sharing.can_write_document?(socket.assigns.current_share_id, socket.assigns.document.id) do
      :ok
    else
      {:error, "permission_denied"}
    end
  end

  defp validate_workspace_write_access(socket) do
    user_id = socket.assigns.current_user_id

    if Workspaces.guest_user?(user_id) do
      validate_guest_write_access(socket, user_id)
    else
      validate_member_write_access(socket.assigns.document.workspace_id, user_id)
    end
  end

  defp validate_member_write_access(workspace_id, user_id) do
    case Workspaces.get_member_with_role(workspace_id, user_id) do
      {_member, role} -> role_write_access_result(role)
      nil -> {:error, "permission_denied"}
    end
  end

  defp role_write_access_result(role) do
    if role_allows_document_write?(role), do: :ok, else: {:error, "permission_denied"}
  end

  defp validate_guest_write_access(socket, user_id) do
    case Workspaces.authorize_guest_permission(
           socket.assigns.document.workspace_id,
           user_id,
           "document:write",
           socket.assigns.document
         ) do
      :ok -> :ok
      {:error, _reason} -> {:error, "permission_denied"}
    end
  end
end
