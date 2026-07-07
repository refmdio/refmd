defmodule RefMD.Storage do
  @moduledoc """
  Configured immutable blob storage used by server-side domains.
  """

  @callback put(String.t(), binary(), keyword()) :: :ok | {:error, atom()}
  @callback get(String.t()) :: {:ok, binary()} | {:error, atom()}
  @callback delete(String.t()) :: :ok | {:error, atom()}
  @callback exists?(String.t()) :: {:ok, boolean()} | {:error, atom()}
  @callback list(String.t(), term()) ::
              {:ok, %{entries: [String.t()], cursor: term() | nil}} | {:error, atom()}

  def put(path, bytes, opts \\ []) when is_binary(path) and is_binary(bytes) and is_list(opts),
    do: backend().put(path, bytes, opts)

  def get(path) when is_binary(path), do: backend().get(path)

  def delete(path) when is_binary(path), do: backend().delete(path)

  def exists?(path) when is_binary(path), do: backend().exists?(path)

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
