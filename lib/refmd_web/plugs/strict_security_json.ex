defmodule RefMDWeb.Plugs.StrictSecurityJson do
  @moduledoc false

  import Plug.Conn
  import Phoenix.Controller

  alias RefMD.Crypto.JCS

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(conn, _opts) do
    raw = IO.iodata_to_binary(conn.private[:raw_body] || "")

    if raw == "" do
      conn
    else
      raw
      |> JCS.parse_json_strict!()
      |> reject_body_signature_transport!()

      conn
    end
  rescue
    ArgumentError ->
      conn
      |> put_status(:unprocessable_entity)
      |> json(%{error: "invalid_strict_json"})
      |> halt()
  end

  defp reject_body_signature_transport!(%{} = value) do
    Enum.each(value, fn {key, nested} ->
      if String.ends_with?(key, "signature_transport") or key == "signature_transport" do
        raise ArgumentError, "signature_transport_forbidden"
      end

      reject_body_signature_transport!(nested)
    end)
  end

  defp reject_body_signature_transport!(value) when is_list(value),
    do: Enum.each(value, &reject_body_signature_transport!/1)

  defp reject_body_signature_transport!(_), do: :ok
end
