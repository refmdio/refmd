defmodule RefMDWeb.SecurityNotificationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Devices, Security, Workspaces}
  alias RefMD.Repo
  alias RefMD.Security.Notification
  alias RefMD.Workspaces.Workspace
  alias RefMDWeb.Schemas

  operation(:index,
    summary: "List security notifications",
    parameters: [
      recipient_kind: [in: :query, type: :string, required: false],
      recipient_id: [in: :query, type: :string, required: false]
    ],
    responses: [
      ok: {"Security notifications", "application/json", Schemas.OkResponse}
    ]
  )

  operation(:read,
    summary: "Mark security notification read",
    parameters: [
      notification_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Security notification", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  operation(:dismiss,
    summary: "Dismiss security notification",
    parameters: [
      notification_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Security notification", "application/json", Schemas.OkResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def index(conn, params) do
    case notification_recipient(conn, params) do
      {:ok, {recipient_kind, recipient_id}} ->
        notifications =
          recipient_kind
          |> Security.list_notifications(recipient_id)
          |> Enum.map(&Notification.payload/1)

        json(conn, %{notifications: notifications})

      {:error, reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: reason})
    end
  end

  def read(conn, %{"notification_id" => notification_id}) do
    update_notification_state(conn, notification_id, &Security.mark_notification_read/3)
  end

  def dismiss(conn, %{"notification_id" => notification_id}) do
    update_notification_state(conn, notification_id, &Security.dismiss_notification/3)
  end

  defp notification_recipient(conn, %{"recipient_kind" => kind, "recipient_id" => id})
       when is_binary(kind) and is_binary(id) do
    with :ok <- authorize_notification_recipient(conn, kind, id) do
      {:ok, {kind, id}}
    end
  end

  defp notification_recipient(conn, _params),
    do: {:ok, {"user", conn.assigns.current_user_id}}

  defp update_notification_state(conn, notification_id, update_fun) do
    case update_fun.(notification_id, "user", conn.assigns.current_user_id) do
      {:ok, notification} ->
        json(conn, %{notification: Notification.payload(notification)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "security_notification_not_found"})
    end
  end

  defp authorize_notification_recipient(conn, "user", user_id) do
    if user_id == conn.assigns.current_user_id do
      :ok
    else
      {:error, "notification_recipient_forbidden"}
    end
  end

  defp authorize_notification_recipient(conn, "device", device_id) do
    if conn.assigns.current_session.device_id == device_id and
         Devices.user_owns_active_device?(conn.assigns.current_user_id, device_id) do
      :ok
    else
      {:error, "notification_recipient_forbidden"}
    end
  end

  defp authorize_notification_recipient(conn, "workspace_role", workspace_id) do
    user_id = conn.assigns.current_user_id

    case Repo.get(Workspace, workspace_id) do
      %Workspace{owner_id: ^user_id} ->
        :ok

      %Workspace{} ->
        if Workspaces.get_member_role(workspace_id, user_id) in ["owner", "admin"] do
          :ok
        else
          {:error, "notification_recipient_forbidden"}
        end

      nil ->
        {:error, "notification_recipient_forbidden"}
    end
  end

  defp authorize_notification_recipient(conn, "pending_registration", registration_id) do
    user_id = conn.assigns.current_user_id

    if Devices.user_owns_device_registration?(user_id, registration_id) or
         Devices.user_owns_active_device?(user_id, registration_id) do
      :ok
    else
      {:error, "notification_recipient_forbidden"}
    end
  end

  defp authorize_notification_recipient(_conn, _kind, _id),
    do: {:error, "notification_recipient_forbidden"}
end
