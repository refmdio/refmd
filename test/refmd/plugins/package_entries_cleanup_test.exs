defmodule RefMD.Plugins.PackageEntriesCleanupTest do
  use RefMD.DataCase, async: false

  alias RefMD.Crypto.Hash
  alias RefMD.Plugins.PackageEntries
  alias RefMD.Plugins.PluginPackageEntry
  alias RefMD.Repo
  alias RefMD.Storage
  alias RefMD.Users.User
  alias RefMD.Workers.CleanupPluginPackageStorage

  setup do
    previous_storage = Application.get_env(:refmd, :storage)
    base_path = Path.join(System.tmp_dir!(), "refmd-package-cleanup-#{System.unique_integer()}")

    Application.put_env(:refmd, :storage, mode: "local", local: [base_path: base_path])

    on_exit(fn ->
      File.rm_rf!(base_path)
      restore_env(:storage, previous_storage)
    end)

    {:ok, user: insert_user!()}
  end

  test "retries pending package entry storage deletion and removes inactive metadata", %{
    user: user
  } do
    path = storage_path()
    bytes = "pending package bytes"

    assert :ok = Storage.put(path, bytes)
    entry = insert_entry!(user, path, bytes, status: "orphan_pending_delete")

    assert {:ok, stats} = PackageEntries.cleanup_storage()

    assert stats.pending_deleted == 1
    assert stats.failed == 0
    assert Repo.get(PluginPackageEntry, entry.id) == nil
    assert {:error, :not_found} = Storage.get(path)
  end

  test "scan deletes package storage objects that have no database entry" do
    path = storage_path()
    assert :ok = Storage.put(path, "stale package bytes")

    assert {:ok, stats} = PackageEntries.cleanup_storage()

    assert stats.scanned_deleted == 1
    assert stats.failed == 0
    assert {:error, :not_found} = Storage.get(path)
  end

  test "scan protects active pinned package entries", %{user: user} do
    path = storage_path()
    bytes = "active package bytes"

    assert :ok = Storage.put(path, bytes)
    entry = insert_entry!(user, path, bytes, status: "pinned")

    assert {:ok, stats} = PackageEntries.cleanup_storage()

    assert stats.protected == 1
    assert Repo.get(PluginPackageEntry, entry.id)
    assert {:ok, ^bytes} = Storage.get(path)
  end

  test "worker invokes package storage cleanup" do
    path = storage_path()
    assert :ok = Storage.put(path, "worker cleanup bytes")

    assert :ok = CleanupPluginPackageStorage.perform(%Oban.Job{})
    assert {:error, :not_found} = Storage.get(path)
  end

  test "worker uses the Plugins facade instead of internal package entries module" do
    source = File.read!("lib/refmd/workers/cleanup_plugin_package_storage.ex")

    refute source =~ "RefMD.Plugins.PackageEntries"
    assert source =~ "Plugins.cleanup_package_storage()"
  end

  test "package storage cleanup worker is scheduled" do
    oban_config = Application.fetch_env!(:refmd, Oban)

    {Oban.Plugins.Cron, cron_opts} =
      Enum.find(oban_config[:plugins], &match?({Oban.Plugins.Cron, _}, &1))

    assert {"*/30 * * * *", CleanupPluginPackageStorage} in cron_opts[:crontab]
  end

  defp insert_entry!(user, path, bytes, opts) do
    status = Keyword.fetch!(opts, :status)
    entry_id = entry_id_from_storage_path(path)

    deleted_at =
      if status in ["orphan_pending_delete", "rejected"] do
        DateTime.utc_now()
      end

    %PluginPackageEntry{id: entry_id}
    |> PluginPackageEntry.changeset(%{
      owner_scope_kind: "user",
      owner_user_id: user.id,
      entry_kind: "resource",
      logical_path: "resources/#{Ecto.UUID.generate()}.txt",
      resource_kind: "text",
      media_type: "text/plain",
      byte_length: byte_size(bytes),
      hash: Hash.blake3_base64url(bytes),
      storage_path: path,
      status: status,
      deleted_at: deleted_at
    })
    |> Repo.insert!()
  end

  defp insert_user! do
    Repo.insert!(%User{
      email: "package-cleanup-#{System.unique_integer([:positive])}@example.com",
      name: "Package Cleanup"
    })
  end

  defp storage_path, do: "plugin-packages/#{Ecto.UUID.generate()}"

  defp entry_id_from_storage_path("plugin-packages/" <> entry_id), do: entry_id

  defp restore_env(key, nil), do: Application.delete_env(:refmd, key)
  defp restore_env(key, value), do: Application.put_env(:refmd, key, value)
end
