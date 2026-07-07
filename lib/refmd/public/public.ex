defmodule RefMD.Public do
  @moduledoc """
  Public document read model.
  """

  import Ecto.Query

  alias RefMD.Crypto.Blake3
  alias RefMD.Documents.Document
  alias RefMD.Public.{PublicAuthorProfile, PublicDocument}
  alias RefMD.Repo
  alias RefMD.Workspaces.Workspace

  @max_content_bytes 1_048_576
  @reserved_slugs MapSet.new(
                    ~w(index feed sitemap p api share auth document dashboard mounts invite)
                  )

  def upsert_author_profile(workspace_id, attrs) when is_binary(workspace_id) and is_map(attrs) do
    with {:ok, display_name} <- fetch_string(attrs, "public_author_display_name"),
         {:ok, slug_base} <- normalize_slug(Map.get(attrs, "public_author_slug"), display_name),
         {:ok, bio} <- fetch_optional_string(attrs, "public_author_bio") do
      profile = Repo.get(PublicAuthorProfile, workspace_id) || %PublicAuthorProfile{}
      slug = public_author_slug(profile, slug_base)

      profile
      |> PublicAuthorProfile.changeset(%{
        workspace_id: workspace_id,
        display_name: display_name,
        slug: slug,
        bio: bio
      })
      |> Repo.insert_or_update()
      |> case do
        {:ok, profile} -> {:ok, serialize_author_profile(profile)}
        {:error, changeset} -> {:error, changeset}
      end
    end
  end

  def get_author_profile(workspace_id) when is_binary(workspace_id) do
    case Repo.get(PublicAuthorProfile, workspace_id) do
      %PublicAuthorProfile{} = profile -> serialize_author_profile(profile)
      nil -> nil
    end
  end

  def create_publication(document_id, user_id, attrs)
      when is_binary(document_id) and is_binary(user_id) and is_map(attrs) do
    Repo.transaction(fn ->
      case Repo.get(Document, document_id) do
        %Document{doc_type: "document"} = document ->
          create_publication_tx(document, user_id, attrs)

        _ ->
          Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  def get_publication(document_id) when is_binary(document_id) do
    case public_document_with_author(document_id) do
      %PublicDocument{} = public_document -> {:ok, serialize_publication(public_document)}
      nil -> {:error, :not_found}
    end
  end

  def update_publication(document_id, attrs) when is_binary(document_id) and is_map(attrs) do
    Repo.transaction(fn ->
      case public_document_with_author(document_id) do
        %PublicDocument{} = public_document -> update_publication_tx(public_document, attrs)
        nil -> Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  def delete_publication(document_id) when is_binary(document_id) do
    Repo.transaction(fn ->
      case locked_public_document(document_id) do
        %PublicDocument{} = public_document ->
          Repo.delete!(public_document)
          broadcast_public_state(public_document.document_id, false, nil)
          :ok

        nil ->
          Repo.rollback(:not_found)
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  def update_publication_content(document_id, attrs)
      when is_binary(document_id) and is_map(attrs) do
    with {:ok, title} <- fetch_string(attrs, "title"),
         {:ok, content} <- fetch_string(attrs, "content"),
         {:ok, content_hash} <- fetch_string(attrs, "content_hash"),
         :ok <- validate_content_size(content),
         :ok <- validate_content_hash(title, content, content_hash) do
      update_publication_content_record(document_id, %{
        title: title,
        content: content,
        content_hash: content_hash
      })
    end
  end

  def resolve_public_document(author_slug, document_slug)
      when is_binary(author_slug) and is_binary(document_slug) do
    case get_public_document_with_author(author_slug, document_slug) do
      {public_document, author_profile} ->
        {:ok, serialize_public_page(public_document, author_profile)}

      nil ->
        {:error, :not_found}
    end
  end

  def list_author_documents(author_slug) when is_binary(author_slug) do
    case get_enabled_author_profile(author_slug) do
      %PublicAuthorProfile{} = author_profile ->
        documents =
          from(p in PublicDocument,
            where: p.author_profile_id == ^author_profile.workspace_id,
            order_by: [desc: p.published_at],
            select: p
          )
          |> Repo.all()
          |> Enum.map(&serialize_public_list_item/1)

        {:ok,
         %{
           author_slug: author_profile.slug,
           author_name: author_profile.display_name,
           author_description: author_profile.bio,
           documents: documents
         }}

      nil ->
        {:error, :not_found}
    end
  end

  def handle_document_deleted(document_id) when is_binary(document_id) do
    if Repo.exists?(from(p in PublicDocument, where: p.document_id == ^document_id)) do
      :published_deleted
    else
      :ok
    end
  end

  def broadcast_unpublished(document_id) when is_binary(document_id) do
    broadcast_public_state(document_id, false, nil)
    :ok
  end

  def published?(document_id) when is_binary(document_id) do
    Repo.exists?(from(p in PublicDocument, where: p.document_id == ^document_id))
  end

  def get_public_state(document_id) when is_binary(document_id) do
    case Repo.get(PublicDocument, document_id) do
      %PublicDocument{} = public_document ->
        %{is_published: true, updated_at: public_document.updated_at}

      nil ->
        %{is_published: false, updated_at: nil}
    end
  end

  def content_hash(title, content) when is_binary(title) and is_binary(content) do
    Blake3.hash_base64url(title <> "\n" <> content)
  end

  defp create_publication_tx(document, user_id, attrs) do
    with nil <- Repo.get(PublicDocument, document.id),
         %Workspace{public_publishing_enabled: true} <- Repo.get(Workspace, document.workspace_id),
         %PublicAuthorProfile{} = author_profile <-
           Repo.get(PublicAuthorProfile, document.workspace_id),
         {:ok, title} <- fetch_string(attrs, "title"),
         {:ok, content} <- fetch_string(attrs, "content"),
         {:ok, content_hash} <- fetch_string(attrs, "content_hash"),
         {:ok, noindex} <- fetch_boolean(attrs, "noindex", false),
         {:ok, slug} <- normalize_slug(Map.get(attrs, "slug"), title),
         :ok <- validate_content_size(content),
         :ok <- validate_content_hash(title, content, content_hash),
         :ok <- validate_slug_available(author_profile.workspace_id, slug, document.id) do
      now = DateTime.utc_now()

      public_document =
        %PublicDocument{}
        |> PublicDocument.changeset(%{
          document_id: document.id,
          workspace_id: document.workspace_id,
          author_profile_id: author_profile.workspace_id,
          slug: slug,
          title: title,
          content: content,
          content_hash: content_hash,
          noindex: noindex,
          published_by: user_id,
          published_at: now,
          updated_at: now
        })
        |> Repo.insert!()
        |> Repo.preload(:author_profile)

      broadcast_public_state(public_document)
      serialize_publication(public_document)
    else
      %PublicDocument{} -> Repo.rollback(:already_published)
      %Workspace{public_publishing_enabled: false} -> Repo.rollback(:public_publishing_disabled)
      nil -> Repo.rollback(:public_author_profile_required)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp update_publication_tx(public_document, attrs) do
    with %Workspace{public_publishing_enabled: true} <-
           Repo.get(Workspace, public_document.workspace_id),
         {:ok, update_attrs} <- fetch_publication_settings(attrs),
         :ok <- validate_new_slug_available(public_document, update_attrs) do
      public_document =
        public_document
        |> PublicDocument.settings_changeset(update_attrs)
        |> Repo.update!()
        |> Repo.preload(:author_profile)

      broadcast_public_state(public_document)
      serialize_publication(public_document)
    else
      %Workspace{public_publishing_enabled: false} -> Repo.rollback(:public_publishing_disabled)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp update_publication_content_record(document_id, attrs) do
    Repo.transaction(fn ->
      case locked_public_document(document_id) do
        %PublicDocument{} = public_document ->
          update_enabled_publication_content(public_document, attrs)

        nil ->
          Repo.rollback(:not_found)
      end
    end)
    |> normalize_transaction_result()
  end

  defp locked_public_document(document_id) do
    Repo.one(
      from(p in PublicDocument,
        where: p.document_id == ^document_id,
        lock: "FOR UPDATE"
      )
    )
  end

  defp update_enabled_publication_content(public_document, attrs) do
    case Repo.get(Workspace, public_document.workspace_id) do
      %Workspace{public_publishing_enabled: true} ->
        if public_document.content_hash == attrs.content_hash do
          %{updated_at: public_document.updated_at}
        else
          update_publication_content_fields(public_document, attrs)
        end

      _ ->
        Repo.rollback(:public_publishing_disabled)
    end
  end

  defp update_publication_content_fields(public_document, attrs) do
    public_document =
      public_document
      |> PublicDocument.content_changeset(attrs)
      |> Repo.update!()

    broadcast_public_state(public_document)
    %{updated_at: public_document.updated_at}
  end

  defp fetch_publication_settings(attrs) do
    Enum.reduce_while(["slug", "noindex"], {:ok, %{}}, fn key, {:ok, acc} ->
      if Map.has_key?(attrs, key) do
        fetch_publication_setting(key, attrs[key], acc)
      else
        {:cont, {:ok, acc}}
      end
    end)
  end

  defp fetch_publication_setting("slug", value, acc) do
    case normalize_slug(value, nil) do
      {:ok, slug} -> {:cont, {:ok, Map.put(acc, :slug, slug)}}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp fetch_publication_setting("noindex", value, acc) when is_boolean(value) do
    {:cont, {:ok, Map.put(acc, :noindex, value)}}
  end

  defp fetch_publication_setting("noindex", _value, _acc), do: {:halt, {:error, :invalid_value}}

  defp normalize_slug(nil, title) when is_binary(title), do: title |> slugify() |> ensure_slug()

  defp normalize_slug(value, _title) when is_binary(value),
    do: value |> slugify() |> ensure_slug()

  defp normalize_slug(_value, _title), do: {:error, :invalid_slug}

  defp ensure_slug(slug) when slug in ["", "-"], do: {:ok, random_slug()}

  defp ensure_slug(slug) do
    slug = String.slice(slug, 0, 128) |> String.trim("-")

    cond do
      slug == "" -> {:ok, random_slug()}
      MapSet.member?(@reserved_slugs, slug) -> {:error, :invalid_slug}
      true -> {:ok, slug}
    end
  end

  defp slugify(value) do
    value
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]+/u, "-")
    |> String.replace(~r/-+/, "-")
    |> String.trim("-")
  end

  defp public_author_slug(%PublicAuthorProfile{slug: slug}, slug) when is_binary(slug), do: slug

  defp public_author_slug(_profile, slug_base) do
    suffix = random_id()
    max_base_length = 64 - byte_size(suffix) - 1

    base =
      slug_base
      |> String.slice(0, max_base_length)
      |> String.trim("-")
      |> ensure_author_slug_base()

    "#{base}-#{suffix}"
  end

  defp ensure_author_slug_base(""), do: "author"
  defp ensure_author_slug_base(slug), do: slug

  defp random_id do
    :crypto.strong_rand_bytes(4)
    |> Base.encode16(case: :lower)
  end

  defp random_slug do
    random = Base.url_encode64(:crypto.strong_rand_bytes(6), padding: false)
    String.downcase("doc-" <> random)
  end

  defp validate_content_size(content) do
    if byte_size(content) <= @max_content_bytes, do: :ok, else: {:error, :content_too_large}
  end

  defp validate_content_hash(title, content, hash) do
    if content_hash(title, content) == hash, do: :ok, else: {:error, :invalid_hash}
  end

  defp validate_new_slug_available(_public_document, attrs) when not is_map_key(attrs, :slug),
    do: :ok

  defp validate_new_slug_available(public_document, %{slug: slug}) do
    if slug == public_document.slug do
      :ok
    else
      validate_slug_available(
        public_document.author_profile_id,
        slug,
        public_document.document_id
      )
    end
  end

  defp validate_slug_available(author_profile_id, slug, document_id) do
    if Repo.exists?(
         from(p in PublicDocument,
           where:
             p.author_profile_id == ^author_profile_id and p.slug == ^slug and
               p.document_id != ^document_id
         )
       ) do
      {:error, {:slug_conflict, suggest_slug(author_profile_id, slug)}}
    else
      :ok
    end
  end

  defp suggest_slug(author_profile_id, slug) do
    Stream.iterate(2, &(&1 + 1))
    |> Enum.find_value(fn suffix ->
      candidate = "#{String.slice(slug, 0, 124)}-#{suffix}"
      if slug_available_for_suggestion?(author_profile_id, candidate), do: candidate
    end)
  end

  defp slug_available_for_suggestion?(author_profile_id, slug) do
    not Repo.exists?(
      from(p in PublicDocument,
        where: p.author_profile_id == ^author_profile_id and p.slug == ^slug
      )
    )
  end

  defp public_document_with_author(document_id) do
    from(p in PublicDocument,
      where: p.document_id == ^document_id,
      preload: [:author_profile]
    )
    |> Repo.one()
  end

  defp get_enabled_author_profile(author_slug) do
    from(a in PublicAuthorProfile,
      join: w in Workspace,
      on: w.id == a.workspace_id,
      where: a.slug == ^author_slug and w.public_publishing_enabled == true,
      select: a
    )
    |> Repo.one()
  end

  defp get_public_document_with_author(author_slug, document_slug) do
    from(p in PublicDocument,
      join: a in PublicAuthorProfile,
      on: a.workspace_id == p.author_profile_id,
      join: w in Workspace,
      on: w.id == p.workspace_id,
      where:
        a.slug == ^author_slug and p.slug == ^document_slug and
          w.public_publishing_enabled == true,
      select: {p, a}
    )
    |> Repo.one()
  end

  defp broadcast_public_state(public_document) do
    broadcast_public_state(public_document.document_id, true, public_document.updated_at)
  end

  defp broadcast_public_state(document_id, is_published, updated_at) do
    Phoenix.PubSub.broadcast(
      RefMD.PubSub,
      "document:#{document_id}",
      %Phoenix.Socket.Broadcast{
        topic: "document:#{document_id}",
        event: "public-status-changed",
        payload: %{
          is_published: is_published,
          updated_at: updated_at
        }
      }
    )
  end

  defp serialize_author_profile(profile) do
    %{
      slug: profile.slug,
      display_name: profile.display_name,
      bio: profile.bio
    }
  end

  defp serialize_publication(public_document) do
    public_document = Repo.preload(public_document, :author_profile)

    %{
      document_id: public_document.document_id,
      slug: public_document.slug,
      url: public_url(public_document),
      noindex: public_document.noindex,
      published_at: public_document.published_at,
      updated_at: public_document.updated_at
    }
  end

  defp serialize_public_page(public_document, author_profile) do
    %{
      document_id: public_document.document_id,
      slug: public_document.slug,
      title: public_document.title,
      content: public_document.content,
      author_slug: author_profile.slug,
      author_name: author_profile.display_name,
      author_description: author_profile.bio,
      noindex: public_document.noindex,
      published_at: public_document.published_at,
      updated_at: public_document.updated_at
    }
  end

  defp serialize_public_list_item(public_document) do
    %{
      slug: public_document.slug,
      title: public_document.title,
      excerpt: markdown_summary(public_document.content),
      noindex: public_document.noindex,
      published_at: public_document.published_at,
      updated_at: public_document.updated_at
    }
  end

  defp markdown_summary(content) do
    content
    |> String.replace(~r/```.*?```/s, " ")
    |> String.replace(~r/`([^`]*)`/, "\\1")
    |> String.replace(~r/!\[([^\]]*)\]\([^)]+\)/, "\\1")
    |> String.replace(~r/\[([^\]]+)\]\([^)]+\)/, "\\1")
    |> String.replace(~r/[#>*_\-\[\]()`]/, " ")
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
    |> String.slice(0, 160)
  end

  defp public_url(public_document) do
    author_profile =
      public_document.author_profile ||
        Repo.get!(PublicAuthorProfile, public_document.author_profile_id)

    "/@#{author_profile.slug}/#{public_document.slug}"
  end

  defp fetch_string(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :invalid_value}
    end
  end

  defp fetch_optional_string(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} when is_binary(value) -> {:ok, if(value == "", do: nil, else: value)}
      {:ok, nil} -> {:ok, nil}
      :error -> {:ok, nil}
      _ -> {:error, :invalid_value}
    end
  end

  defp fetch_boolean(attrs, key, default) do
    case Map.fetch(attrs, key) do
      {:ok, value} when is_boolean(value) -> {:ok, value}
      :error -> {:ok, default}
      _ -> {:error, :invalid_value}
    end
  end

  defp normalize_transaction_result({:ok, value}), do: {:ok, value}
  defp normalize_transaction_result({:error, reason}), do: {:error, reason}
end
