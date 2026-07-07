defmodule RefMD.Plugins.BundleCandidates do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Plugins.{
    Artifact,
    PackageEntries,
    PluginApplication,
    PluginBundleCandidate,
    PluginPackage,
    SourceArchives
  }

  alias RefMD.Repo
  alias RefMD.Security

  def get(id), do: Repo.get(PluginBundleCandidate, id)

  def create_local(path, attrs) when is_binary(path) and is_map(attrs) do
    create_local(path, attrs, [])
  end

  def create_local(path, attrs, opts)
      when is_binary(path) and is_map(attrs) and is_list(opts) do
    record_fetch_requested =
      Keyword.get(opts, :record_fetch_requested, &Security.record_plugin_fetch_requested/1)

    record_fetch_completed =
      Keyword.get(opts, :record_fetch_completed, &Security.record_plugin_fetch_completed/1)

    audit_attrs = Map.merge(attrs, %{source_kind: "local_upload", source_url: nil})

    with {:requested, {:ok, _}} <- {:requested, record_fetch_requested.(audit_attrs)},
         {:artifact, {:ok, candidate_attrs}} <-
           {:artifact,
            Artifact.candidate_attrs_from_archive_path(path, :local_upload, nil, attrs)},
         {:authorized, :ok} <- {:authorized, authorize_candidate(candidate_attrs, opts)},
         {:completed, {:ok, _}} <- {:completed, record_fetch_completed.(candidate_attrs)} do
      create_validated(candidate_attrs)
    else
      {_audit, {:error, %Ecto.Changeset{}} = error} ->
        error

      {:artifact, {:error, reason} = error} ->
        record_validation_failed_or_error(audit_attrs, reason, error)

      {:authorized, {:error, reason}} ->
        {:error, reason}

      {_audit, {:error, reason}} when is_atom(reason) ->
        {:error, reason}
    end
  end

  def create_remote(source_url, attrs) when is_binary(source_url) and is_map(attrs) do
    create_remote(source_url, attrs, [])
  end

  def create_remote(source_url, attrs, opts)
      when is_binary(source_url) and is_map(attrs) and is_list(opts) do
    case SourceArchives.fetch_archive(source_url, remote_fetch_opts(attrs, opts)) do
      {:ok, archive_path, canonical_url} ->
        try do
          create_from_archive_path(
            archive_path,
            :remote_https_url,
            canonical_url,
            attrs,
            opts
          )
        after
          File.rm(archive_path)
        end

      {:error, _reason} = error ->
        error
    end
  end

  defp remote_fetch_opts(attrs, opts) do
    opts
    |> Keyword.put(:audit_attrs, Map.merge(attrs, %{source_kind: "remote_https_url"}))
    |> Keyword.put_new(:record_fetch_requested, &Security.record_plugin_fetch_requested/1)
    |> Keyword.put_new(:record_fetch_completed, &Security.record_plugin_fetch_completed/1)
    |> Keyword.put_new(:record_fetch_failed, &Security.record_plugin_fetch_failed/2)
  end

  def create_from_archive_path(path, source_kind, source_url, attrs)
      when is_binary(path) and is_map(attrs) do
    create_from_archive_path(path, source_kind, source_url, attrs, [])
  end

  def create_from_archive_path(path, source_kind, source_url, attrs, opts)
      when is_binary(path) and is_map(attrs) and is_list(opts) do
    case Artifact.candidate_attrs_from_archive_path(path, source_kind, source_url, attrs) do
      {:ok, candidate_attrs} ->
        with :ok <- authorize_candidate(candidate_attrs, opts) do
          create_validated(candidate_attrs)
        end

      {:error, reason} = error ->
        record_validation_failed_or_error(
          Map.merge(attrs, %{source_kind: to_string(source_kind), source_url: source_url}),
          reason,
          error
        )
    end
  end

  defp authorize_candidate(candidate_attrs, opts) do
    opts
    |> Keyword.get(:authorize_candidate, fn _candidate_attrs -> :ok end)
    |> then(fn authorize -> authorize.(candidate_attrs) end)
  end

  defp record_validation_failed_or_error(attrs, reason, original_error) do
    case Security.record_plugin_artifact_validation_failed(attrs, reason) do
      {:ok, _} -> original_error
      {:error, audit_error} -> {:error, audit_error}
    end
  end

  defp create_validated(candidate_attrs) do
    candidate_attrs =
      candidate_attrs
      |> put_owner_ids()
      |> put_package_id()

    Repo.transaction(fn -> insert_tx(candidate_attrs) end)
  end

  defp put_package_id(%{package_id: package_id} = attrs) when is_binary(package_id), do: attrs

  defp put_package_id(%{application_id: application_id} = attrs) when is_binary(application_id) do
    case Repo.get(PluginApplication, application_id) do
      %PluginApplication{package_id: package_id} when is_binary(package_id) ->
        Map.put(attrs, :package_id, package_id)

      _ ->
        Map.put(attrs, :package_id, Ecto.UUID.generate())
    end
  end

  defp put_package_id(
         %{owner_scope_kind: "workspace", owner_workspace_id: workspace_id, plugin_id: plugin_id} =
           attrs
       )
       when is_binary(workspace_id) and is_binary(plugin_id) do
    attrs
    |> put_existing_package_id(
      from(p in PluginPackage,
        where:
          p.owner_scope_kind == "workspace" and p.owner_workspace_id == ^workspace_id and
            p.plugin_id == ^plugin_id,
        order_by: [desc: p.created_at],
        limit: 1
      )
    )
  end

  defp put_package_id(
         %{owner_scope_kind: "user", owner_user_id: user_id, plugin_id: plugin_id} = attrs
       )
       when is_binary(user_id) and is_binary(plugin_id) do
    attrs
    |> put_existing_package_id(
      from(p in PluginPackage,
        where:
          p.owner_scope_kind == "user" and p.owner_user_id == ^user_id and
            p.plugin_id == ^plugin_id,
        order_by: [desc: p.created_at],
        limit: 1
      )
    )
  end

  defp put_package_id(attrs), do: Map.put(attrs, :package_id, Ecto.UUID.generate())

  defp put_existing_package_id(attrs, query) do
    case Repo.one(query) do
      %PluginPackage{id: package_id} -> Map.put(attrs, :package_id, package_id)
      nil -> Map.put(attrs, :package_id, Ecto.UUID.generate())
    end
  end

  defp put_owner_ids(%{owner_scope_kind: "workspace", workspace_id: workspace_id} = attrs) do
    attrs
    |> Map.put_new(:owner_workspace_id, workspace_id)
    |> Map.put_new(:owner_user_id, nil)
  end

  defp put_owner_ids(%{owner_scope_kind: "workspace", routing_workspace_id: workspace_id} = attrs)
       when is_binary(workspace_id) do
    attrs
    |> Map.delete(:routing_workspace_id)
    |> Map.put(:workspace_id, workspace_id)
    |> Map.put_new(:owner_workspace_id, workspace_id)
    |> Map.put_new(:owner_user_id, nil)
  end

  defp put_owner_ids(%{owner_scope_kind: "user", created_by_user_id: user_id} = attrs) do
    attrs
    |> Map.delete(:routing_workspace_id)
    |> Map.put_new(:workspace_id, nil)
    |> Map.put_new(:owner_user_id, user_id)
    |> Map.put_new(:owner_workspace_id, nil)
  end

  defp put_owner_ids(attrs), do: attrs

  defp insert_tx(candidate_attrs) do
    package_entries = Map.get(candidate_attrs, :package_entries, [])

    %PluginBundleCandidate{}
    |> PluginBundleCandidate.changeset(candidate_attrs)
    |> Repo.insert()
    |> case do
      {:ok, candidate} ->
        case PackageEntries.create_candidate_entries(candidate, package_entries) do
          {:ok, entries} ->
            record_created_or_cleanup(candidate, entries)

          {:error, reason} ->
            Repo.rollback(reason)
        end

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp record_created_or_cleanup(candidate, entries) do
    with {:ok, _} <- Security.record_plugin_candidate_created(candidate),
         {:ok, _} <- record_update_available(candidate) do
      candidate
    else
      {:error, reason} ->
        PackageEntries.cleanup_entries(entries)
        Repo.rollback(reason)
    end
  end

  defp record_update_available(%PluginBundleCandidate{application_id: application_id} = candidate)
       when is_binary(application_id) do
    case Repo.get(RefMD.Plugins.PluginApplication, application_id) do
      %{current_bundle_id: current_bundle_id} when is_binary(current_bundle_id) ->
        Security.record_plugin_bundle_update_available(candidate)

      _ ->
        {:ok, :not_update}
    end
  end

  defp record_update_available(_candidate), do: {:ok, :not_update}
end
