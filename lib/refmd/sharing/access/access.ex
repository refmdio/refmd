defmodule RefMD.Sharing.Access do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo

  alias RefMD.Sharing.{
    Participants,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareKey,
    ShareParticipantSession
  }

  @max_safe_integer 9_007_199_254_740_991

  @spec get_share_permission(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, String.t()} | {:error, :not_found}
  def get_share_permission(share_id, document_id) do
    case active_share_for_document(share_id, document_id) do
      %Share{permission: permission} -> {:ok, permission}
      _ -> {:error, :not_found}
    end
  end

  @spec can_read_document?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def can_read_document?(share_id, document_id) do
    match?({:ok, _permission}, get_share_permission(share_id, document_id))
  end

  @spec can_write_document?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def can_write_document?(share_id, document_id) do
    match?({:ok, "edit"}, get_share_permission(share_id, document_id))
  end

  @spec can_continue_document_session?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def can_continue_document_session?(share_id, document_id) do
    match?(%Share{}, active_share_for_document(share_id, document_id))
  end

  @spec can_join_document_session?(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def can_join_document_session?(share_id, document_id, session_id) do
    match?(%Share{}, active_participant_share_for_document(share_id, document_id, session_id))
  end

  @spec share_accepting_participants?(Share.t()) :: boolean()
  def share_accepting_participants?(%Share{} = share) do
    not expired?(share) and not max_views_reached?(share)
  end

  @spec share_session_accessible?(Share.t()) :: boolean()
  def share_session_accessible?(%Share{} = share) do
    not expired?(share)
  end

  @spec share_session_accessible_now?(Ecto.UUID.t()) :: boolean()
  def share_session_accessible_now?(share_id) do
    from(s in Share, where: s.id == ^share_id)
    |> Repo.one()
    |> case do
      %Share{} = share -> share_session_accessible?(share)
      _ -> false
    end
  end

  @spec share_session_workspace_access?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def share_session_workspace_access?(share_id, workspace_id) do
    case current_workspace_event_sequence(workspace_id) do
      {:ok, current_sequence} ->
        Repo.exists?(
          from(s in Share,
            join: d in Document,
            on: d.id == s.document_id,
            where:
              s.id == ^share_id and d.workspace_id == ^workspace_id and
                s.expires_event_sequence > ^current_sequence
          )
        )

      _ ->
        false
    end
  end

  @spec expired?(Share.t()) :: boolean()
  def expired?(%Share{expires_event_sequence: @max_safe_integer}), do: false

  def expired?(%Share{} = share) do
    with {:ok, workspace_id} <- share_workspace_id(share),
         {:ok, current_sequence} <- current_workspace_event_sequence(workspace_id) do
      share.expires_event_sequence <= current_sequence
    else
      _ -> true
    end
  end

  @spec max_views_reached?(Share.t()) :: boolean()
  def max_views_reached?(%Share{max_views: @max_safe_integer}), do: false

  def max_views_reached?(%Share{max_views: max_views, view_count: view_count}) do
    view_count >= max_views
  end

  defp share_workspace_id(%Share{document: %Document{workspace_id: workspace_id}}),
    do: {:ok, workspace_id}

  defp share_workspace_id(%Share{document_id: document_id}) do
    case Repo.get(Document, document_id) do
      %Document{workspace_id: workspace_id} -> {:ok, workspace_id}
      _ -> :error
    end
  end

  defp current_workspace_event_sequence(workspace_id) do
    case Encryption.current_workspace_key_directory_pin(workspace_id) do
      %{event_head_sequence: sequence} when is_integer(sequence) and sequence > 0 ->
        {:ok, sequence}

      _ ->
        :error
    end
  end

  @spec document_accessible_in_share?(Share.t(), Ecto.UUID.t()) :: boolean()
  def document_accessible_in_share?(%Share{scope: "document"} = share, document_id) do
    document_in_share_scope?(share, document_id)
  end

  def document_accessible_in_share?(%Share{scope: "folder"} = share, document_id) do
    case Repo.get(Document, document_id) do
      %Document{} = document ->
        document.doc_type == "document" and folder_share_entry_accessible?(share, document)

      _ ->
        false
    end
  end

  @spec folder_share_entry_accessible?(Share.t(), Document.t()) :: boolean()
  def folder_share_entry_accessible?(%Share{} = share, %Document{} = document) do
    is_nil(document.archived_at) and
      document_in_share_scope?(share, document.id) and
      not document_excluded_in_share?(share.id, document.id) and
      folder_child_share_ready?(share.id, document.id) and
      folder_share_parent_path_accessible?(share.id, share.document_id, document)
  end

  @spec folder_token_accessible_in_share?(Share.t(), Share.t(), SharedFolderToken.t()) ::
          boolean()
  def folder_token_accessible_in_share?(
        %Share{} = access_share,
        %Share{} = token_share,
        %SharedFolderToken{} = token
      ) do
    cond do
      token_share.id == access_share.id ->
        access_share.scope == "folder" and token.document_id == access_share.document_id

      token_share.parent_share_id == access_share.id ->
        token_share.scope == "folder" and token_share.document_id == token.document_id and
          folder_token_document_accessible?(access_share, token.document_id)

      true ->
        false
    end
  end

  @spec folder_token_document_accessible?(Share.t(), Ecto.UUID.t()) :: boolean()
  def folder_token_document_accessible?(%Share{} = access_share, document_id) do
    case Repo.get(Document, document_id) do
      %Document{} = document -> folder_share_entry_accessible?(access_share, document)
      _ -> false
    end
  end

  @spec descendant_of?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def descendant_of?(document_id, ancestor_id) do
    sql = """
    WITH RECURSIVE ancestors AS (
      SELECT id, parent_id
      FROM documents
      WHERE id = $1
      UNION ALL
      SELECT d.id, d.parent_id
      FROM documents d
      INNER JOIN ancestors a ON d.id = a.parent_id
    )
    SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $2)
    """

    case Repo.query(sql, [Ecto.UUID.dump!(document_id), Ecto.UUID.dump!(ancestor_id)]) do
      {:ok, %{rows: [[value]]}} -> value == true
      _ -> false
    end
  end

  @spec folder_child_share_ready?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def folder_child_share_ready?(root_share_id, document_id) do
    from(s in Share,
      join: d in Document,
      on: d.id == s.document_id,
      join: sk in ShareKey,
      on: sk.share_id == s.id,
      left_join: dt in SharedDocumentToken,
      on: dt.share_id == s.id and dt.document_id == s.document_id,
      left_join: ft in SharedFolderToken,
      on: ft.share_id == s.id and ft.document_id == s.document_id,
      where: s.parent_share_id == ^root_share_id,
      where: s.document_id == ^document_id,
      where: s.scope == d.doc_type,
      where:
        fragment(
          "(? = 'folder' AND ? IS NOT NULL) OR (? = 'document' AND ? IS NOT NULL)",
          d.doc_type,
          ft.share_id,
          d.doc_type,
          dt.share_id
        )
    )
    |> Repo.exists?()
  end

  defp active_share_for_document(share_id, document_id) do
    case find_share_access_payload(share_id) do
      %{access_share: %Share{} = access_share} = payload ->
        if share_session_accessible?(access_share) and
             share_access_payload_matches_document?(payload, document_id) and
             document_accessible_in_share?(access_share, document_id),
           do: access_share,
           else: nil

      _ ->
        nil
    end
  end

  defp active_participant_share_for_document(share_id, document_id, session_id) do
    with %{access_share: %Share{} = access_share} = payload <- find_share_access_payload(share_id),
         {:ok, %ShareParticipantSession{} = session} <-
           Participants.get_valid_participant_session_by_id(session_id),
         %Share{} <- active_share_for_document(session.share_id, document_id),
         true <- share_access_payload_matches_document?(payload, document_id),
         true <- document_accessible_in_share?(access_share, document_id),
         true <- share_session_accessible?(access_share) do
      access_share
    else
      _ -> nil
    end
  end

  defp share_access_payload_matches_document?(
         %{share: %Share{parent_share_id: nil}},
         _document_id
       ),
       do: true

  defp share_access_payload_matches_document?(
         %{share: %Share{document_id: document_id}},
         document_id
       ),
       do: true

  defp share_access_payload_matches_document?(_payload, _document_id), do: false

  defp find_share_access_payload(share_id) do
    from(s in Share,
      left_join: root in Share,
      on: root.id == s.parent_share_id,
      where: s.id == ^share_id,
      select: %{share: s, root_share: root}
    )
    |> Repo.one()
    |> case do
      nil -> nil
      %{share: share, root_share: nil} = payload -> Map.put(payload, :access_share, share)
      %{root_share: root_share} = payload -> Map.put(payload, :access_share, root_share)
    end
  end

  defp document_in_share_scope?(%Share{scope: "document", document_id: root_id}, document_id),
    do: root_id == document_id

  defp document_in_share_scope?(%Share{scope: "folder", document_id: root_folder_id}, document_id) do
    descendant_of?(document_id, root_folder_id)
  end

  defp folder_share_parent_path_accessible?(
         _root_share_id,
         root_folder_id,
         %Document{parent_id: parent_id}
       )
       when parent_id == root_folder_id,
       do: true

  defp folder_share_parent_path_accessible?(
         _root_share_id,
         _root_folder_id,
         %Document{parent_id: nil}
       ),
       do: false

  defp folder_share_parent_path_accessible?(
         root_share_id,
         root_folder_id,
         %Document{parent_id: parent_id}
       ) do
    with %Document{} = parent <- Repo.get(Document, parent_id),
         true <- folder_child_share_ready?(root_share_id, parent_id) do
      folder_share_parent_path_accessible?(root_share_id, root_folder_id, parent)
    else
      _ -> false
    end
  end

  defp document_excluded_in_share?(share_id, document_id) do
    sql = """
    WITH RECURSIVE ancestors AS (
      SELECT id, parent_id
      FROM documents
      WHERE id = $1
      UNION ALL
      SELECT d.id, d.parent_id
      FROM documents d
      INNER JOIN ancestors a ON d.id = a.parent_id
    )
    SELECT EXISTS(
      SELECT 1
      FROM share_exclusions e
      INNER JOIN ancestors a ON a.id = e.document_id
      WHERE e.share_id = $2
    )
    """

    case Repo.query(sql, [Ecto.UUID.dump!(document_id), Ecto.UUID.dump!(share_id)]) do
      {:ok, %{rows: [[value]]}} -> value == true
      _ -> true
    end
  end
end
