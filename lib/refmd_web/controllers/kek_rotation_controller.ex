defmodule RefMDWeb.KekRotationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Devices, Encryption, Workspaces}
  alias RefMDWeb.Schemas

  operation(:start_kek_rotation,
    summary: "Start KEK rotation for a workspace (manual trigger)",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Rotation started", "application/json", Schemas.KekRotationStartResponse},
      not_found: {"Workspace not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse},
      conflict: {"Rotation already in progress", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec start_kek_rotation(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def start_kek_rotation(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    base_role = Workspaces.get_member_role(workspace_id, user_id)

    if base_role in ~w(owner admin) do
      case Workspaces.start_kek_rotation(workspace_id, user_id) do
        {:ok, _} ->
          json(conn, %{workspace_id: workspace_id, needs_kek_rotation: true})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

        {:error, :kek_rotation_already_in_progress} ->
          conn |> put_status(:conflict) |> json(%{error: "kek_rotation_already_in_progress"})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  end

  operation(:complete_kek_rotation,
    summary: "Complete KEK rotation for a workspace",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Completion params", "application/json", Schemas.KekRotationCompleteRequest},
    responses: [
      ok: {"Rotation completed", "application/json", Schemas.OkResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Preconditions not met", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec complete_kek_rotation(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def complete_kek_rotation(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    new_kek_version = params["new_kek_version"]

    if not is_integer(new_kek_version) or new_kek_version <= 0 do
      conn |> put_status(:bad_request) |> json(%{error: "invalid_kek_version"})
    else
      with {:ok, workspace} <- fetch_workspace(workspace_id),
           {:ok, base_role} <- fetch_membership(workspace_id, user_id),
           :ok <- require_rotation_in_progress(workspace),
           :ok <- require_rotation_authority(workspace, user_id, base_role) do
        envelope_checks = build_envelope_checks(workspace_id, user_id, new_kek_version)

        Workspaces.complete_kek_rotation(workspace_id, new_kek_version,
          envelope_checks: envelope_checks
        )
        |> handle_rotation_completion(conn)
      else
        {:error, status, error} ->
          conn |> put_status(status) |> json(%{error: error})
      end
    end
  end

  operation(:save_member_envelopes,
    summary: "Save member envelopes for KEK rotation",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Member envelopes", "application/json", Schemas.SaveMemberEnvelopesRequest},
    responses: [
      ok: {"Envelopes saved", "application/json", Schemas.OkResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec save_member_envelopes(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def save_member_envelopes(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]
    envelopes = params["envelopes"] || []

    with {:ok, workspace} <- fetch_workspace(workspace_id),
         {:ok, base_role} <- fetch_membership(workspace_id, user_id),
         :ok <- require_rotation_in_progress(workspace),
         :ok <- require_rotation_authority(workspace, user_id, base_role),
         :ok <- validate_envelope_senders(envelopes, pop_device_id) do
      case Encryption.save_member_envelopes(workspace_id, envelopes) do
        {:ok, _} ->
          json(conn, %{ok: true})

        {:error, _} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "save_failed"})
      end
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:get_member_envelope,
    summary: "Get own member envelope for KEK recovery",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    responses: [
      ok: {"Member envelope", "application/json", Schemas.MemberEnvelopeResponse},
      forbidden: {"Not a member", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  @spec get_member_envelope(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def get_member_envelope(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id

    if Workspaces.get_member_role(workspace_id, user_id) == nil do
      conn |> put_status(:forbidden) |> json(%{error: "not_a_member"})
    else
      render_member_envelope(conn, workspace_id, user_id)
    end
  end

  # --- Private helpers ---

  defp fetch_workspace(workspace_id) do
    case Workspaces.get_workspace(workspace_id) do
      nil -> {:error, :not_found, "workspace_not_found"}
      workspace -> {:ok, workspace}
    end
  end

  defp fetch_membership(workspace_id, user_id) do
    case Workspaces.get_member_role(workspace_id, user_id) do
      nil -> {:error, :forbidden, "not_a_member"}
      role -> {:ok, role}
    end
  end

  defp require_rotation_in_progress(workspace) do
    if workspace.needs_kek_rotation do
      :ok
    else
      {:error, :unprocessable_entity, "not_in_rotation"}
    end
  end

  defp require_rotation_authority(workspace, user_id, base_role) do
    if workspace.kek_rotation_initiator_user_id == user_id or base_role in ~w(owner admin) do
      :ok
    else
      {:error, :forbidden, "forbidden"}
    end
  end

  defp validate_envelope_senders(envelopes, pop_device_id) do
    has_invalid =
      Enum.any?(envelopes, fn env ->
        env["sender_device_id"] != pop_device_id
      end)

    if has_invalid do
      {:error, :forbidden, "sender_device_id_mismatch"}
    else
      :ok
    end
  end

  defp build_envelope_checks(workspace_id, user_id, new_kek_version) do
    fn ->
      cond do
        not Encryption.all_user_devices_have_key?(workspace_id, user_id, new_kek_version) ->
          {:error, :missing_device_envelopes}

        not Encryption.all_members_have_envelope?(workspace_id, new_kek_version) ->
          {:error, :missing_member_envelopes}

        true ->
          :ok
      end
    end
  end

  defp handle_rotation_completion(result, conn) do
    case result do
      :ok ->
        json(conn, %{ok: true})

      {:error, :not_in_rotation} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "not_in_rotation"})

      {:error, :version_not_monotonic} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "version_not_monotonic"})

      {:error, :not_found} ->
        conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

      {:error, :missing_device_envelopes} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_device_envelopes"})

      {:error, :missing_member_envelopes} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_member_envelopes"})
    end
  end

  defp render_member_envelope(conn, workspace_id, user_id) do
    case Encryption.get_member_envelope(workspace_id, user_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      envelope ->
        case Devices.get_device(envelope.sender_device_id) do
          nil ->
            conn |> put_status(:not_found) |> json(%{error: "not_found"})

          sender ->
            json(conn, %{
              key_version: envelope.key_version,
              sender_device_id: envelope.sender_device_id,
              sender_user_id: sender.user_id,
              sender_ecdh_public_key: encode_binary(sender.ecdh_public_key),
              sender_signing_public_key: encode_binary(sender.signing_public_key),
              encrypted_kek: encode_binary(envelope.encrypted_kek),
              nonce: encode_binary(envelope.nonce)
            })
        end
    end
  end
end
