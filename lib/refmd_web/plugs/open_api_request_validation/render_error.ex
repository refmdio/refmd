defmodule RefMDWeb.Plugs.OpenApiRequestValidation.RenderError do
  @moduledoc false

  import Phoenix.Controller
  import Plug.Conn

  @spec init(term()) :: term()
  def init(errors), do: errors

  @spec call(Plug.Conn.t(), term()) :: Plug.Conn.t()
  def call(conn, errors) do
    conn
    |> put_status(:unprocessable_entity)
    |> json(%{error: "invalid_request_schema", details: format_errors(errors)})
  end

  defp format_errors(errors) when is_list(errors), do: Enum.map(errors, &format_error/1)
  defp format_errors(error), do: [format_error(error)]

  defp format_error(%{reason: reason, path: path}) do
    %{path: path || [], reason: inspect(reason)}
  end

  defp format_error(error), do: %{reason: inspect(error)}
end
