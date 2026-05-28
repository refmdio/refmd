defmodule RefMD.Plugins.PackageEntries do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Hash
  alias RefMD.Plugins.PluginPackageEntry
  alias RefMD.Repo
  alias RefMD.Storage

  @package_prefix "plugin-packages/"

  @type raw_entry :: %{
          required(:entry_kind) => String.t(),
          required(:logical_path) => String.t(),
          required(:media_type) => String.t(),
          required(:bytes) => binary(),
          optional(:resource_kind) => String.t() | nil
        }

  @spec storage_path(Ecto.UUID.t()) :: String.t()
  def storage_path(entry_id), do: @package_prefix <> entry_id

  @spec create_candidate_entries(struct(), [raw_entry()]) ::
          {:ok, [PluginPackageEntry.t()]} | {:error, Ecto.Changeset.t() | atom()}
  def create_candidate_entries(candidate, raw_entries) when is_list(raw_entries) do
    Enum.reduce_while(raw_entries, {:ok, []}, fn raw_entry, {:ok, acc} ->
      entry_id = generate_entry_id()
      bytes = Map.fetch!(raw_entry, :bytes)
      path = storage_path(entry_id)

      attrs =
        raw_entry
        |> Map.drop([:bytes])
        |> Map.merge(%{
          id: entry_id,
          owner_scope_kind: candidate.owner_scope_kind,
          owner_workspace_id: candidate.owner_workspace_id,
          owner_user_id: candidate.owner_user_id,
          candidate_id: candidate.id,
          byte_length: byte_size(bytes),
          hash: Hash.blake3_base64url(bytes),
          storage_path: path,
          status: "candidate"
        })

      case put_and_insert(path, bytes, attrs) do
        {:ok, entry} -> {:cont, {:ok, [entry | acc]}}
        {:error, reason} -> {:halt, {:error, reason, acc}}
      end
    end)
    |> case do
      {:ok, entries} -> {:ok, Enum.reverse(entries)}
      {:error, reason, entries} -> cleanup_written_entries(entries, reason)
      error -> error
    end
  end

  @spec cleanup_entries([PluginPackageEntry.t()]) :: :ok
  def cleanup_entries(entries) when is_list(entries) do
    Enum.each(entries, fn entry ->
      _ = Storage.delete(entry.storage_path)
    end)

    :ok
  end

  @spec cleanup_storage(keyword()) :: {:ok, map()} | {:error, atom()}
  def cleanup_storage(opts \\ []) when is_list(opts) do
    stats = %{pending_deleted: 0, scanned_deleted: 0, protected: 0, failed: 0}

    stats
    |> retry_pending_deletes()
    |> scan_storage(nil, Keyword.get(opts, :max_pages, :infinity))
  end

  @spec pin_candidate_entries(struct(), struct(), struct()) ::
          {:ok, [PluginPackageEntry.t()]} | {:error, Ecto.Changeset.t() | atom()}
  def pin_candidate_entries(candidate, package, bundle) do
    entries =
      Repo.all(
        from(e in PluginPackageEntry,
          where: e.candidate_id == ^candidate.id and e.status == "candidate",
          order_by: [asc: e.logical_path]
        )
      )

    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      with {:ok, _bytes} <- verified_bytes(entry),
           {:ok, updated} <-
             entry
             |> PluginPackageEntry.changeset(
               entry_attrs(entry, %{
                 bundle_id: bundle.id,
                 package_id: package.id,
                 status: "pinned",
                 pinned_at: DateTime.utc_now()
               })
             )
             |> Repo.update() do
        {:cont, {:ok, [updated | acc]}}
      else
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, updated} -> {:ok, Enum.reverse(updated)}
      error -> error
    end
  end

  @spec bundle_bytes(Ecto.UUID.t()) ::
          {:ok, %{String.t() => binary()}} | {:error, atom()}
  def bundle_bytes(bundle_id) do
    with {:ok, entries} <- bundle_entries(bundle_id) do
      {:ok, Map.new(entries, fn %{entry: entry, bytes: bytes} -> {entry.logical_path, bytes} end)}
    end
  end

  @spec bundle_entries(Ecto.UUID.t()) ::
          {:ok, [%{entry: PluginPackageEntry.t(), bytes: binary()}]} | {:error, atom()}
  def bundle_entries(bundle_id) do
    entries =
      Repo.all(
        from(e in PluginPackageEntry,
          where: e.bundle_id == ^bundle_id and e.status == "pinned",
          order_by: [asc: e.logical_path]
        )
      )

    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case verified_bytes(entry) do
        {:ok, bytes} -> {:cont, {:ok, [%{entry: entry, bytes: bytes} | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, entries} -> {:ok, Enum.reverse(entries)}
      error -> error
    end
  end

  defp put_and_insert(path, bytes, attrs) do
    case Storage.put(path, bytes, []) do
      :ok ->
        case %PluginPackageEntry{id: attrs.id}
             |> PluginPackageEntry.changeset(attrs)
             |> Repo.insert() do
          {:ok, entry} ->
            {:ok, entry}

          {:error, reason} ->
            _ = Storage.delete(path)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp cleanup_written_entries(entries, reason) do
    Enum.each(entries, fn entry ->
      _ =
        entry
        |> PluginPackageEntry.changeset(
          entry_attrs(entry, %{
            status: "orphan_pending_delete",
            deleted_at: DateTime.utc_now()
          })
        )
        |> Repo.update()

      _ = Storage.delete(entry.storage_path)
    end)

    {:error, reason}
  end

  defp retry_pending_deletes(stats) do
    entries =
      Repo.all(
        from(e in PluginPackageEntry,
          where:
            e.status in ["orphan_pending_delete", "rejected"] or
              not is_nil(e.deleted_at),
          order_by: [asc: e.storage_path]
        )
      )

    Enum.reduce(entries, stats, &cleanup_entry_storage(&2, &1.storage_path, :pending_deleted))
  end

  defp scan_storage(stats, _cursor, 0), do: {:ok, stats}

  defp scan_storage(stats, cursor, pages_left) do
    with {:ok, %{entries: paths, cursor: next_cursor}} <- Storage.list(@package_prefix, cursor) do
      stats = Enum.reduce(paths, stats, &cleanup_entry_storage(&2, &1, :scanned_deleted))

      case next_cursor do
        nil -> {:ok, stats}
        next -> scan_storage(stats, next, next_page_limit(pages_left))
      end
    end
  end

  defp next_page_limit(:infinity), do: :infinity
  defp next_page_limit(pages_left) when is_integer(pages_left), do: pages_left - 1

  defp cleanup_entry_storage(stats, storage_path, deleted_key) do
    case delete_storage_if_inactive(storage_path) do
      :deleted -> Map.update!(stats, deleted_key, &(&1 + 1))
      :protected -> Map.update!(stats, :protected, &(&1 + 1))
      {:error, _reason} -> Map.update!(stats, :failed, &(&1 + 1))
    end
  end

  defp delete_storage_if_inactive(storage_path) do
    Repo.transaction(fn -> delete_storage_if_inactive_tx(storage_path) end)
    |> case do
      {:ok, result} -> result
      {:error, reason} -> {:error, reason}
    end
  end

  defp delete_storage_if_inactive_tx(storage_path) do
    entries =
      Repo.all(
        from(e in PluginPackageEntry,
          where: e.storage_path == ^storage_path,
          lock: "FOR UPDATE"
        )
      )

    if Enum.any?(entries, &active_entry?/1) do
      :protected
    else
      delete_inactive_storage(storage_path, entries)
    end
  end

  defp delete_inactive_storage(storage_path, entries) do
    case Storage.delete(storage_path) do
      :ok ->
        delete_inactive_entry_rows(entries)
        :deleted

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp active_entry?(%PluginPackageEntry{status: status, deleted_at: nil})
       when status in ["candidate", "pinned"],
       do: true

  defp active_entry?(%PluginPackageEntry{}), do: false

  defp delete_inactive_entry_rows([]), do: {0, nil}

  defp delete_inactive_entry_rows(entries) do
    ids = Enum.map(entries, & &1.id)
    Repo.delete_all(from(e in PluginPackageEntry, where: e.id in ^ids))
  end

  defp entry_attrs(entry, attrs) do
    %{
      owner_scope_kind: entry.owner_scope_kind,
      owner_workspace_id: entry.owner_workspace_id,
      owner_user_id: entry.owner_user_id,
      candidate_id: entry.candidate_id,
      bundle_id: entry.bundle_id,
      package_id: entry.package_id,
      entry_kind: entry.entry_kind,
      logical_path: entry.logical_path,
      resource_kind: entry.resource_kind,
      media_type: entry.media_type,
      byte_length: entry.byte_length,
      hash: entry.hash,
      storage_path: entry.storage_path,
      status: entry.status,
      pinned_at: entry.pinned_at,
      deleted_at: entry.deleted_at
    }
    |> Map.merge(attrs)
  end

  defp verified_bytes(%PluginPackageEntry{} = entry) do
    with {:ok, bytes} <- Storage.get(entry.storage_path),
         true <- byte_size(bytes) == entry.byte_length,
         true <- Hash.blake3_base64url(bytes) == entry.hash do
      {:ok, bytes}
    else
      false -> {:error, :plugin_bundle_runtime_hash_mismatch}
      {:error, _reason} -> {:error, :plugin_package_entry_missing}
    end
  end

  defp generate_entry_id do
    timestamp_ms = System.system_time(:millisecond)
    <<rand_a::12, rand_b::62, _rest::6>> = :crypto.strong_rand_bytes(10)

    <<timestamp_ms::48, 7::4, rand_a::12, 0b10::2, rand_b::62>>
    |> encode_uuid()
  end

  defp encode_uuid(bytes) do
    hex = Base.encode16(bytes, case: :lower)

    <<part1::binary-size(8), part2::binary-size(4), part3::binary-size(4), part4::binary-size(4),
      part5::binary-size(12)>> = hex

    Enum.join([part1, part2, part3, part4, part5], "-")
  end
end
