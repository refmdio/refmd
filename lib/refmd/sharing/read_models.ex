defmodule RefMD.Sharing.ReadModels do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.Document
  alias RefMD.Repo

  alias RefMD.Sharing.{
    Access,
    ServerEnvelope,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareKey,
    VerificationDirectories
  }

  @spec find_document_token_payload(String.t()) :: map() | nil
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

  @spec find_folder_token_payload(String.t()) :: map() | nil
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

  @spec get_root_document_token(Ecto.UUID.t(), Ecto.UUID.t()) :: SharedDocumentToken.t() | nil
  def get_root_document_token(share_id, document_id) do
    from(t in SharedDocumentToken,
      where: t.share_id == ^share_id and t.document_id == ^document_id
    )
    |> Repo.one()
  end

  @spec get_root_folder_token(Ecto.UUID.t(), Ecto.UUID.t()) :: SharedFolderToken.t() | nil
  def get_root_folder_token(share_id, document_id) do
    from(t in SharedFolderToken,
      where: t.share_id == ^share_id and t.document_id == ^document_id
    )
    |> Repo.one()
  end

  @spec authorized_document_bootstrap(
          Share.t(),
          Share.t(),
          ShareKey.t(),
          SharedDocumentToken.t(),
          Document.t(),
          String.t(),
          String.t() | nil
        ) :: {:ok, map()} | {:error, :not_found}
  def authorized_document_bootstrap(
        access_share,
        token_share,
        share_key,
        token,
        document,
        session_grant,
        share_slug
      ) do
    case ServerEnvelope.decrypt_share_dek(
           share_key.encrypted_dek,
           share_key.dek_server_nonce,
           share_key.server_key_id,
           token_share.id,
           token.document_id
         ) do
      {:ok, encrypted_dek} ->
        {:ok,
         %{
           share_slug: share_slug,
           share_id: token_share.id,
           document_id: token.document_id,
           workspace_id: document.workspace_id,
           title: document.title,
           encrypted_title: document.encrypted_title,
           encrypted_title_nonce: document.encrypted_title_nonce,
           encrypted_title_key_version: document.encrypted_title_key_version,
           key_version: document.min_dek_version,
           permission: session_grant,
           password_protected: access_share.password_protected,
           encrypted_dek: encrypted_dek,
           nonce: share_key.nonce,
           verification_directory:
             VerificationDirectories.verification_directory(access_share.id, token.document_id)
         }}

      {:error, _reason} ->
        {:error, :not_found}
    end
  end

  @spec build_authorized_folder_bootstrap(
          Share.t(),
          Share.t(),
          SharedFolderToken.t(),
          String.t() | nil
        ) :: {:ok, map()} | {:error, :not_found}
  def build_authorized_folder_bootstrap(
        %Share{} = access_share,
        %Share{} = token_share,
        %SharedFolderToken{} = token,
        share_slug
      ) do
    with %Document{} = folder <- Repo.get(Document, token.document_id),
         true <- folder.doc_type == "folder",
         %{} = folder_row <- serialize_share_tree_row(access_share, token_share, folder, token) do
      entries = list_folder_share_entries(access_share, folder.id)
      folder_row = Map.put(folder_row, :parent_id, nil)

      {:ok,
       %{
         share_slug: share_slug,
         share_id: access_share.id,
         password_protected: access_share.password_protected,
         verification_directory:
           VerificationDirectories.verification_directory(access_share.id, folder.id),
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
         %Share{} = _access_share,
         %Share{} = token_share,
         %Document{} = document,
         token
       ) do
    with %ShareKey{} = share_key <- Repo.get(ShareKey, token_share.id),
         {:ok, encrypted_dek} <-
           ServerEnvelope.decrypt_share_dek(
             share_key.encrypted_dek,
             share_key.dek_server_nonce,
             share_key.server_key_id,
             token_share.id,
             document.id
           ) do
      %{
        id: document.id,
        share_id: token_share.id,
        doc_type: document.doc_type,
        parent_id: document.parent_id,
        position: document.position,
        title: document.title,
        encrypted_title: document.encrypted_title,
        encrypted_title_nonce: document.encrypted_title_nonce,
        encrypted_title_key_version: document.encrypted_title_key_version,
        key_version: document.min_dek_version,
        encrypted_dek: encrypted_dek,
        nonce: share_key.nonce
      }
      |> put_share_tree_token(token)
    else
      _ -> nil
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
