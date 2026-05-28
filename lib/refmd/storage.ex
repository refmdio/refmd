defmodule RefMD.Storage do
  @moduledoc """
  Configured immutable blob storage used by server-side domains.
  """

  @type storage_path :: String.t()
  @type cursor :: term()

  @callback put(storage_path(), binary(), keyword()) :: :ok | {:error, atom()}
  @callback get(storage_path()) :: {:ok, binary()} | {:error, atom()}
  @callback delete(storage_path()) :: :ok | {:error, atom()}
  @callback exists?(storage_path()) :: {:ok, boolean()} | {:error, atom()}
  @callback list(String.t(), cursor()) ::
              {:ok, %{entries: [storage_path()], cursor: cursor() | nil}} | {:error, atom()}

  @spec put(storage_path(), binary(), keyword()) :: :ok | {:error, atom()}
  def put(path, bytes, opts \\ []) when is_binary(path) and is_binary(bytes) and is_list(opts),
    do: backend().put(path, bytes, opts)

  @spec get(storage_path()) :: {:ok, binary()} | {:error, atom()}
  def get(path) when is_binary(path), do: backend().get(path)

  @spec delete(storage_path()) :: :ok | {:error, atom()}
  def delete(path) when is_binary(path), do: backend().delete(path)

  @spec exists?(storage_path()) :: {:ok, boolean()} | {:error, atom()}
  def exists?(path) when is_binary(path), do: backend().exists?(path)

  @spec list(String.t(), cursor()) ::
          {:ok, %{entries: [storage_path()], cursor: cursor() | nil}} | {:error, atom()}
  def list(prefix, cursor \\ nil) when is_binary(prefix), do: backend().list(prefix, cursor)

  defp backend do
    :refmd
    |> Application.get_env(:storage, [])
    |> Keyword.get(:mode, "local")
    |> case do
      "local" -> RefMD.Storage.Local
      :local -> RefMD.Storage.Local
      "s3" -> RefMD.Storage.S3
      :s3 -> RefMD.Storage.S3
      _ -> raise ArgumentError, "storage_mode_invalid"
    end
  end
end
