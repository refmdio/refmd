defmodule RefMD.Storage.Local do
  @moduledoc false

  @behaviour RefMD.Storage

  @impl true
  def put(path, bytes, _opts) when is_binary(path) and is_binary(bytes) do
    with {:ok, absolute} <- absolute_path(path),
         false <- File.exists?(absolute),
         :ok <- File.mkdir_p(Path.dirname(absolute)) do
      File.write(absolute, bytes, [:binary, :exclusive])
    else
      true -> {:error, :storage_conflict}
      {:error, reason} -> {:error, normalize_error(reason)}
    end
  end

  @impl true
  def get(path) when is_binary(path) do
    with {:ok, absolute} <- absolute_path(path) do
      case File.read(absolute) do
        {:ok, bytes} -> {:ok, bytes}
        {:error, :enoent} -> {:error, :not_found}
        {:error, reason} -> {:error, normalize_error(reason)}
      end
    end
  end

  @impl true
  def delete(path) when is_binary(path) do
    with {:ok, absolute} <- absolute_path(path) do
      case File.rm(absolute) do
        :ok -> :ok
        {:error, :enoent} -> :ok
        {:error, reason} -> {:error, normalize_error(reason)}
      end
    end
  end

  @impl true
  def exists?(path) when is_binary(path) do
    with {:ok, absolute} <- absolute_path(path) do
      {:ok, File.exists?(absolute)}
    end
  end

  @impl true
  def list(prefix, cursor) when is_binary(prefix) and prefix == "plugin-packages/" do
    root = root_path()
    offset = if is_integer(cursor) and cursor >= 0, do: cursor, else: 0

    entries =
      root
      |> Path.join(prefix)
      |> list_files()
      |> Enum.map(&Path.relative_to(&1, root))
      |> Enum.sort()

    page = Enum.slice(entries, offset, 100)
    next = if offset + length(page) < length(entries), do: offset + length(page), else: nil
    {:ok, %{entries: page, cursor: next}}
  end

  def list(_prefix, _cursor), do: {:error, :invalid_prefix}

  defp list_files(path) do
    case File.ls(path) do
      {:ok, names} ->
        Enum.flat_map(names, &list_child_files(path, &1))

      {:error, :enoent} ->
        []

      {:error, _reason} ->
        []
    end
  end

  defp list_child_files(path, name) do
    child = Path.join(path, name)
    if File.dir?(child), do: list_files(child), else: [child]
  end

  defp absolute_path(path) do
    if valid_storage_path?(path) do
      {:ok, Path.join(root_path(), path)}
    else
      {:error, :invalid_path}
    end
  end

  defp valid_storage_path?(path) do
    path != "" and not String.starts_with?(path, "/") and
      not String.contains?(path, ["\\", <<0>>, "../", "/..", "//"])
  end

  defp root_path do
    :refmd
    |> Application.get_env(:storage, [])
    |> Keyword.get(:local, [])
    |> Keyword.get(:base_path, Path.join(System.tmp_dir!(), "refmd-storage"))
  end

  defp normalize_error(reason), do: reason
end
