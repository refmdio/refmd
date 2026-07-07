defmodule RefMD.Documents.Access do
  @moduledoc false

  alias RefMD.Workspaces

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

  defp share_participant_socket?(%{assigns: %{session_kind: :share_participant}}), do: true
  defp share_participant_socket?(_socket), do: false

  defp role_allows_document_write?(role) do
    role
    |> Workspaces.effective_permissions()
    |> MapSet.member?("document:write")
  end
end
