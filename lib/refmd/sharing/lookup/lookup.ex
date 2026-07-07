defmodule RefMD.Sharing.Lookup do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Sharing.Verification.Directory

  alias RefMD.Sharing.{
    Access,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareKey
  }

  def find_document_token_payload(document_token) do
    from(t in SharedDocumentToken,
      join: s in Share,
      on: s.id == t.share_id,
      left_join: ps in Share,
      on: ps.id == s.parent_share_id,
      join: sk in ShareKey,
      on: sk.share_id == s.id,
      join: d in Document,
      on: d.id == t.document_id,
      where: t.token == ^document_token,
      select: %{token: t, share: s, root_share: ps, share_key: sk, document: d}
    )
    |> Repo.one()
    |> normalize_document_token_payload()
  end

  def find_folder_token_payload(folder_token) do
    from(t in SharedFolderToken,
      join: s in Share,
      on: s.id == t.share_id,
      left_join: root in Share,
      on: root.id == s.parent_share_id,
      where: t.token == ^folder_token,
      select: %{token: t, share: s, root_share: root}
    )
    |> Repo.one()
    |> normalize_folder_token_payload()
  end

  def get_root_document_token(share_id, document_id) do
    from(t in SharedDocumentToken,
      where: t.share_id == ^share_id and t.document_id == ^document_id
    )
    |> Repo.one()
  end

  def get_root_folder_token(share_id, document_id) do
    from(t in SharedFolderToken,
      where: t.share_id == ^share_id and t.document_id == ^document_id
    )
    |> Repo.one()
  end

  def authorized_document_bootstrap(
        access_share,
        token_share,
        share_key,
        token,
        document,
        session_grant,
        share_token_hash
      ) do
    workspace_key_directory =
      workspace_key_directory_bootstrap_material(
        document.workspace_id,
        access_share.authenticated_workspace_pin_bootstrap_checkpoint
      )

    {:ok,
     %{
       share_token_hash: share_token_hash,
       share_id: token_share.id,
       authorization_share_id: access_share.id,
       scope_kind: access_share.scope,
       scope_id: access_share.document_id,
       created_event_hash: access_share.created_event_hash,
       latest_bootstrap_event_hash: access_share.latest_bootstrap_event_hash,
       capability_context_hash: access_share.capability_context_hash,
       share_capability_secret_commitment: access_share.share_capability_secret_commitment,
       password_capability_secret_commitment: access_share.password_capability_secret_commitment,
       document_id: token.document_id,
       workspace_id: document.workspace_id,
       encrypted_title: document.encrypted_title,
       encrypted_title_nonce: document.encrypted_title_nonce,
       encrypted_title_key_version: document.encrypted_title_key_version,
       key_version: document.min_dek_version,
       permission: session_grant,
       password_protected: access_share.password_protected,
       encrypted_dek: share_key.encrypted_dek,
       nonce: share_key.nonce,
       workspace_pin_bootstrap: access_share.authenticated_workspace_pin_bootstrap_checkpoint,
       workspace_key_directory_checkpoint: workspace_key_directory.checkpoint,
       workspace_key_directory_latest_checkpoint: workspace_key_directory.latest_checkpoint,
       workspace_key_directory_checkpoint_ancestry: workspace_key_directory.checkpoint_ancestry,
       workspace_key_directory_event_ancestry: workspace_key_directory.event_ancestry,
       verification_directory:
         Directory.verification_directory(access_share.id, token.document_id)
     }}
  end

  def build_authorized_folder_bootstrap(
        %Share{} = access_share,
        %Share{} = token_share,
        %SharedFolderToken{} = token,
        session_grant,
        share_token_hash
      ) do
    with %Document{} = folder <- Repo.get(Document, token.document_id),
         true <- folder.doc_type == "folder",
         %{} = folder_row <- serialize_share_tree_row(access_share, token_share, folder, token) do
      entries = list_folder_share_entries(access_share, folder.id)
      folder_row = Map.put(folder_row, :parent_id, nil)

      workspace_key_directory =
        workspace_key_directory_bootstrap_material(
          folder.workspace_id,
          access_share.authenticated_workspace_pin_bootstrap_checkpoint
        )

      {:ok,
       %{
         share_token_hash: share_token_hash,
         share_id: access_share.id,
         scope_kind: access_share.scope,
         scope_id: access_share.document_id,
         created_event_hash: access_share.created_event_hash,
         latest_bootstrap_event_hash: access_share.latest_bootstrap_event_hash,
         capability_context_hash: access_share.capability_context_hash,
         share_capability_secret_commitment: access_share.share_capability_secret_commitment,
         password_capability_secret_commitment:
           access_share.password_capability_secret_commitment,
         workspace_id: folder.workspace_id,
         permission: session_grant,
         password_protected: access_share.password_protected,
         workspace_pin_bootstrap: access_share.authenticated_workspace_pin_bootstrap_checkpoint,
         workspace_key_directory_checkpoint: workspace_key_directory.checkpoint,
         workspace_key_directory_latest_checkpoint: workspace_key_directory.latest_checkpoint,
         workspace_key_directory_checkpoint_ancestry: workspace_key_directory.checkpoint_ancestry,
         workspace_key_directory_event_ancestry: workspace_key_directory.event_ancestry,
         verification_directory: Directory.verification_directory(access_share.id, folder.id),
         folder: folder_row,
         entries: entries
       }}
    else
      _ -> {:error, :not_found}
    end
  end

  defp normalize_document_token_payload(nil), do: nil

  defp normalize_document_token_payload(%{share: share, root_share: nil} = payload) do
    Map.put(payload, :access_share, share)
  end

  defp normalize_document_token_payload(%{root_share: root_share} = payload) do
    Map.put(payload, :access_share, root_share)
  end

  defp normalize_folder_token_payload(nil), do: nil

  defp normalize_folder_token_payload(%{share: share, root_share: nil} = payload) do
    Map.put(payload, :access_share, share)
  end

  defp normalize_folder_token_payload(%{root_share: root_share} = payload) do
    Map.put(payload, :access_share, root_share)
  end

  defp workspace_key_directory_bootstrap_material(workspace_id, pin_bootstrap) do
    with %{} = payload <- map_field(pin_bootstrap, "payload"),
         sequence when is_integer(sequence) <- map_field(payload, "event_head_sequence"),
         expected_hash when is_binary(expected_hash) <- map_field(payload, "checkpoint_hash"),
         %{checkpoint_hash: ^expected_hash} = checkpoint <-
           Encryption.workspace_key_directory_checkpoint_covering_event_head(
             workspace_id,
             sequence
           ) do
      checkpoint_envelope = key_directory_envelope(checkpoint)

      anchor = %{
        checkpoint_sequence: checkpoint.sequence,
        checkpoint_hash: checkpoint.checkpoint_hash,
        event_head_sequence: checkpoint.covered_event_head_sequence,
        event_head_hash: checkpoint.covered_event_head_hash
      }

      case Encryption.latest_workspace_key_directory_delta(workspace_id, anchor) do
        {:ok, %{checkpoint: latest, checkpoints: checkpoints, events: events}} ->
          %{
            checkpoint: checkpoint_envelope,
            latest_checkpoint: key_directory_envelope(latest),
            checkpoint_ancestry: Enum.map(checkpoints, &key_directory_envelope/1),
            event_ancestry: Enum.map(events, &key_directory_envelope/1)
          }

        _ ->
          %{
            checkpoint: checkpoint_envelope,
            latest_checkpoint: checkpoint_envelope,
            checkpoint_ancestry: [],
            event_ancestry: []
          }
      end
    else
      _ ->
        %{
          checkpoint: nil,
          latest_checkpoint: nil,
          checkpoint_ancestry: [],
          event_ancestry: []
        }
    end
  end

  defp key_directory_envelope(entry), do: %{payload: entry.payload, signatures: entry.signatures}

  defp map_field(%{} = map, key), do: dual_key_get(map, key)
  defp map_field(_, _), do: nil

  defp dual_key_get(map, key) do
    atom_key = atom_key(key)

    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, atom_key)
    end
  end

  defp atom_key("payload"), do: :payload
  defp atom_key("event_head_sequence"), do: :event_head_sequence
  defp atom_key("checkpoint_hash"), do: :checkpoint_hash

  defp list_folder_share_entries(%Share{} = share, folder_id) do
    from(d in Document,
      where: d.parent_id == ^folder_id,
      where: is_nil(d.archived_at),
      order_by: [asc: d.position]
    )
    |> Repo.all()
    |> Enum.map(&serialize_share_tree_row(share, &1))
    |> Enum.reject(&is_nil/1)
  end

  defp serialize_share_tree_row(%Share{} = share, %Document{} = document) do
    if Access.folder_share_entry_accessible?(share, document) do
      serialize_accessible_share_tree_row(share, document)
    end
  end

  defp serialize_accessible_share_tree_row(%Share{} = share, %Document{} = document) do
    case document.doc_type do
      "folder" ->
        case get_child_shared_folder_payload(share.id, document.id) do
          %{share: token_share, token: token} ->
            serialize_share_tree_row(share, token_share, document, token)

          nil ->
            nil
        end

      _ ->
        case get_child_shared_document_payload(share.id, document.id) do
          %{share: token_share, token: token} ->
            serialize_share_tree_row(share, token_share, document, token)

          nil ->
            nil
        end
    end
  end

  defp serialize_share_tree_row(
         %Share{} = access_share,
         %Share{} = token_share,
         %Document{} = document,
         token
       ) do
    case Repo.get(ShareKey, token_share.id) do
      %ShareKey{} = share_key ->
        %{
          id: document.id,
          share_id: token_share.id,
          doc_type: document.doc_type,
          parent_id: document.parent_id,
          position: document.position,
          encrypted_title: document.encrypted_title,
          encrypted_title_nonce: document.encrypted_title_nonce,
          encrypted_title_key_version: document.encrypted_title_key_version,
          key_version: document.min_dek_version,
          encrypted_dek: share_key.encrypted_dek,
          nonce: share_key.nonce,
          workspace_pin_bootstrap: access_share.authenticated_workspace_pin_bootstrap_checkpoint
        }
        |> put_share_tree_token(token)

      _ ->
        nil
    end
  end

  defp put_share_tree_token(row, %SharedFolderToken{} = token) do
    row
    |> Map.put(:folder_token, token.token)
    |> Map.put(:document_token, nil)
  end

  defp put_share_tree_token(row, %SharedDocumentToken{} = token) do
    row
    |> Map.put(:document_token, token.token)
    |> Map.put(:folder_token, nil)
  end

  defp get_child_shared_document_payload(root_share_id, document_id) do
    from(t in SharedDocumentToken,
      join: s in Share,
      on: s.id == t.share_id,
      where:
        s.parent_share_id == ^root_share_id and s.document_id == ^document_id and
          s.scope == "document" and t.document_id == ^document_id,
      select: %{share: s, token: t}
    )
    |> Repo.one()
  end

  defp get_child_shared_folder_payload(root_share_id, document_id) do
    from(t in SharedFolderToken,
      join: s in Share,
      on: s.id == t.share_id,
      where:
        s.parent_share_id == ^root_share_id and s.document_id == ^document_id and
          s.scope == "folder" and t.document_id == ^document_id,
      select: %{share: s, token: t}
    )
    |> Repo.one()
  end
end
