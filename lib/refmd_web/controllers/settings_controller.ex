defmodule RefMDWeb.SettingsController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Users
  alias RefMDWeb.Schemas

  # ── GET /api/settings ──────────────────────────────

  operation(:show,
    summary: "Get current user settings",
    responses: [
      ok: {"User settings", "application/json", Schemas.SettingsResponse},
      not_found: {"Settings not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, _params) do
    user_id = conn.assigns.current_user_id

    case Users.get_user_settings(user_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "settings_not_found"})

      settings ->
        conn |> json(serialize(settings))
    end
  end

  # ── PATCH /api/settings ────────────────────────────

  operation(:update,
    summary: "Update current user settings",
    request_body: {"Settings params", "application/json", Schemas.UpdateSettingsRequest},
    responses: [
      ok: {"Updated settings", "application/json", Schemas.SettingsResponse},
      not_found: {"Settings not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec update(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def update(conn, params) do
    user_id = conn.assigns.current_user_id

    case Users.update_user_settings(user_id, params) do
      {:ok, settings} ->
        conn |> json(serialize(settings))

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "settings_not_found"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "validation_error", details: format_errors(changeset)})
    end
  end

  defp serialize(settings) do
    %{
      theme: settings.theme,
      locale: settings.locale,
      editor_vim_mode: settings.editor_vim_mode,
      editor_font_size: settings.editor_font_size,
      editor_default_mode: settings.editor_default_mode,
      editor_layout_mode: settings.editor_layout_mode
    }
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
