defmodule RefMDWeb.Helpers do
  @moduledoc false

  # --- Binary encoding / decoding ---

  @doc "Base64url-encode a binary value, passing through nil."
  @spec encode_binary(nil) :: nil
  @spec encode_binary(binary()) :: String.t()
  def encode_binary(nil), do: nil
  def encode_binary(bin) when is_binary(bin), do: Base.url_encode64(bin, padding: false)

  @doc "Safely decode a base64url string, returning {:ok, bytes} or {:error, :invalid_base64}."
  @spec decode_binary(term()) :: {:ok, binary()} | {:error, :invalid_base64}
  def decode_binary(base64) when is_binary(base64) do
    case Base.url_decode64(base64, padding: false) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, :invalid_base64}
    end
  end

  def decode_binary(_), do: {:error, :invalid_base64}

  @doc "Decode a required base64url field. Raises on nil or invalid input."
  @spec decode_binary!(term()) :: binary()
  def decode_binary!(base64) when is_binary(base64) do
    Base.url_decode64!(base64, padding: false)
  end

  def decode_binary!(_), do: raise(ArgumentError, "missing required binary field")

  @doc "Decode an optional base64url field. Passes through nil, raises on invalid."
  @spec decode_optional_binary(nil | String.t()) :: nil | binary()
  def decode_optional_binary(nil), do: nil

  def decode_optional_binary(val) when is_binary(val) do
    Base.url_decode64!(val, padding: false)
  end

  # --- Changeset helpers ---

  @doc "Check if a changeset has a unique constraint error."
  @spec has_unique_constraint_error?(Ecto.Changeset.t()) :: boolean()
  def has_unique_constraint_error?(%Ecto.Changeset{} = changeset) do
    Enum.any?(changeset.errors, fn {_field, {_msg, opts}} ->
      Keyword.get(opts, :constraint) == :unique
    end)
  end

  @doc "Format changeset or other errors into a serializable map."
  @spec format_errors(Ecto.Changeset.t() | String.t() | atom() | term()) :: map()
  def format_errors(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  def format_errors(error) when is_binary(error), do: %{base: [error]}
  def format_errors(error) when is_atom(error), do: %{base: [to_string(error)]}
  def format_errors(_), do: %{}

  # --- Session cookie helpers ---

  @spec set_session_cookie(Plug.Conn.t(), binary(), boolean()) :: Plug.Conn.t()
  def set_session_cookie(conn, token, remember_me) do
    token_base64 = Base.url_encode64(token, padding: false)
    max_age = if remember_me, do: 30 * 24 * 60 * 60, else: 24 * 60 * 60

    same_site =
      case Application.get_env(:refmd, :samesite_mode, "lax") do
        "none" -> "None"
        _ -> "Lax"
      end

    opts = [
      path: "/api",
      http_only: true,
      secure:
        Application.get_env(:refmd, :cookie_secure, conn.scheme == :https) or same_site == "None",
      same_site: same_site
    ]

    Plug.Conn.put_resp_cookie(conn, "_refmd_session", token_base64, [{:max_age, max_age} | opts])
  end

  @spec delete_session_cookie(Plug.Conn.t()) :: Plug.Conn.t()
  def delete_session_cookie(conn) do
    Plug.Conn.delete_resp_cookie(conn, "_refmd_session", path: "/api")
  end
end
