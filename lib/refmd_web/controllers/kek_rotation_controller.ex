defmodule RefMDWeb.KekRotationController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.{Devices, Encryption, Workspaces}
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Workspaces.AuthorityMutations
  alias RefMDWeb.Payloads.DeviceIdentity

  alias RefMDWeb.Schemas

  @rotation_parameters [
    workspace_id: [in: :path, type: :string, required: true],
    rotation_id: [in: :path, type: :string, required: true]
  ]

  operation(:start_kek_rotation_intent,
    summary: "Prepare a compound KEK rotation start",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body: {"Start params", "application/json", Schemas.KekRotationStartIntentRequest},
    responses: [
      ok: {"Compound intent", "application/json", Schemas.CompoundAppendIntent},
      not_found: {"Workspace not found", "application/json", Schemas.ErrorResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse},
      conflict: {"Rotation already in progress", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Invalid key directory", "application/json", Schemas.ErrorResponse}
    ]
  )

  def start_kek_rotation_intent(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    base_role = Workspaces.get_member_role(workspace_id, user_id)

    if not Workspaces.guest_user?(user_id) and base_role in ~w(owner admin) do
      case AuthorityMutations.issue_intent(
             user_id,
             conn.assigns[:rrp_device_id],
             "workspace.kek.rotation_started",
             %{
               "workspace_id" => workspace_id,
               "old_key_version" => params["old_key_version"],
               "new_key_version" => params["new_key_version"],
               "reason" => params["reason"],
               "rotation_id" => params["rotation_id"]
             },
             %{"events" => params["events"], "checkpoint" => params["checkpoint"]}
           ) do
        {:ok, intent} ->
          json(conn, intent)

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "workspace_not_found"})

        {:error, :kek_rotation_already_in_progress} ->
          conn |> put_status(:conflict) |> json(%{error: "kek_rotation_already_in_progress"})

        {:error, :forbidden} ->
          conn |> put_status(:forbidden) |> json(%{error: "forbidden"})

        {:error, :invalid_key_directory} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})

        {:error, error} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  end

  operation(:start_kek_rotation,
    summary: "Commit a compound KEK rotation start",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Compound authorization", "application/json", Schemas.CompoundAppendAuthorization},
    responses: [
      ok: {"Committed mutation", "application/json", Schemas.WorkspaceAuthorityMutationResponse},
      forbidden: {"Not authorized", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Invalid mutation", "application/json", Schemas.ErrorResponse}
    ]
  )

  def start_kek_rotation(conn, _params) do
    case AuthorityMutations.commit(
           conn.assigns.current_user_id,
           conn.assigns[:rrp_device_id],
           conn.body_params
         ) do
      {:ok, %{response: response}} ->
        json(conn, response)

      {:error, error} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
    end
  end

  operation(:complete_kek_rotation_intent,
    summary: "Prepare a compound KEK rotation completion",
    parameters: @rotation_parameters,
    request_body:
      {"Completion pre-commit material", "application/json",
       Schemas.KekRotationCompletionIntentRequest},
    responses: [
      ok: {"Compound intent", "application/json", Schemas.CompoundAppendIntent},
      unprocessable_entity: {"Invalid completion", "application/json", Schemas.ErrorResponse}
    ]
  )

  def complete_kek_rotation_intent(conn, params) do
    issue_rotation_intent(conn, params, "workspace.kek.rotation_completed", [
      "old_key_version",
      "new_key_version",
      "device_wrap_precommits",
      "member_envelope_precommits",
      "workspace_invitation_updates",
      "guest_invitation_updates"
    ])
  end

  operation(:complete_kek_rotation,
    summary: "Commit a compound KEK rotation completion",
    parameters: @rotation_parameters,
    request_body:
      {"Compound authorization", "application/json", Schemas.CompoundAppendAuthorization},
    responses: [
      ok: {"Committed mutation", "application/json", Schemas.WorkspaceAuthorityMutationResponse},
      unprocessable_entity: {"Invalid completion", "application/json", Schemas.ErrorResponse}
    ]
  )

  def complete_kek_rotation(conn, params), do: commit_rotation(conn, params)

  operation(:delete_old_kek_intent,
    summary: "Prepare a compound old KEK deletion",
    parameters: @rotation_parameters,
    request_body: {"Deletion proofs", "application/json", Schemas.KekOldKeyDeletionIntentRequest},
    responses: [
      ok: {"Compound intent", "application/json", Schemas.CompoundAppendIntent},
      unprocessable_entity: {"Invalid deletion", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete_old_kek_intent(conn, params) do
    issue_rotation_intent(conn, params, "workspace.kek.old_key_deleted", [
      "old_key_version",
      "deletion_manifest",
      "device_key_deletion_proofs",
      "wipe_required_device_ids"
    ])
  end

  operation(:delete_old_kek,
    summary: "Commit a compound old KEK deletion",
    parameters: @rotation_parameters,
    request_body:
      {"Compound authorization", "application/json", Schemas.CompoundAppendAuthorization},
    responses: [
      ok: {"Committed mutation", "application/json", Schemas.WorkspaceAuthorityMutationResponse},
      unprocessable_entity: {"Invalid deletion", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete_old_kek(conn, params), do: commit_rotation(conn, params)

  defp issue_rotation_intent(conn, params, event_type, command_keys) do
    user_id = conn.assigns.current_user_id
    workspace_id = params["workspace_id"]

    if not Workspaces.guest_user?(user_id) and
         Workspaces.get_member_role(workspace_id, user_id) in ~w(owner admin) do
      command =
        conn.body_params
        |> Map.take(command_keys)
        |> Map.put("workspace_id", workspace_id)
        |> Map.put("rotation_id", params["rotation_id"])

      candidate = %{
        "events" => conn.body_params["events"],
        "checkpoint" => conn.body_params["checkpoint"]
      }

      case AuthorityMutations.issue_intent(
             user_id,
             conn.assigns[:rrp_device_id],
             event_type,
             command,
             candidate
           ) do
        {:ok, intent} ->
          json(conn, intent)

        {:error, error} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
      end
    else
      conn |> put_status(:forbidden) |> json(%{error: "forbidden"})
    end
  end

  defp commit_rotation(conn, params) do
    case AuthorityMutations.commit(
           conn.assigns.current_user_id,
           conn.assigns[:rrp_device_id],
           conn.body_params,
           %{
             "workspace_id" => params["workspace_id"],
             "rotation_id" => params["rotation_id"]
           }
         ) do
      {:ok, %{response: response}} ->
        json(conn, response)

      {:error, error} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(error)})
    end
  end

  operation(:get_workspace_wipe_requirement,
    summary: "Get the current device KEK wipe requirement",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    responses: [
      ok: {"Wipe requirement", "application/json", Schemas.WorkspaceWipeRequirementResponse},
      not_found: {"No wipe requirement", "application/json", Schemas.ErrorResponse},
      forbidden: {"Not a member", "application/json", Schemas.ErrorResponse}
    ]
  )

  def get_workspace_wipe_requirement(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns[:rrp_device_id]

    with true <- is_binary(device_id),
         :ok <- require_workspace_crypto_access(workspace_id, user_id, device_id),
         {:ok, requirement} <- Workspaces.workspace_wipe_requirement(workspace_id, device_id) do
      json(conn, requirement)
    else
      {:error, :forbidden, error} -> conn |> put_status(:forbidden) |> json(%{error: error})
      _ -> conn |> put_status(:not_found) |> json(%{error: "wipe_requirement_not_found"})
    end
  end

  operation(:acknowledge_workspace_wipe,
    summary: "Acknowledge secure deletion for a KEK wipe requirement",
    parameters: [workspace_id: [in: :path, type: :string, required: true]],
    request_body:
      {"Deletion proof", "application/json", Schemas.WorkspaceWipeAcknowledgementRequest},
    responses: [
      ok: {"Acknowledged", "application/json", Schemas.OkResponse},
      forbidden: {"Not a member", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Invalid proof", "application/json", Schemas.ErrorResponse}
    ]
  )

  def acknowledge_workspace_wipe(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns[:rrp_device_id]

    with true <- is_binary(device_id),
         :ok <- require_workspace_crypto_access(workspace_id, user_id, device_id),
         :ok <-
           Workspaces.acknowledge_workspace_wipe(
             workspace_id,
             device_id,
             params["device_key_deletion_proof"]
           ) do
      json(conn, %{ok: true})
    else
      {:error, :forbidden, error} ->
        conn |> put_status(:forbidden) |> json(%{error: error})

      {:error, reason} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: Atom.to_string(reason)})

      _ ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_deletion_proof"})
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

  def save_member_envelopes(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    rrp_device_id = conn.assigns[:rrp_device_id]

    with {:ok, workspace} <- fetch_workspace(workspace_id),
         :ok <- authorize_member_envelope_write(workspace, user_id, rrp_device_id),
         :ok <- reject_wipe_required_device(workspace_id, rrp_device_id),
         {:ok, envelopes} <- require_envelopes(params["envelopes"]),
         :ok <- validate_guest_self_envelopes(workspace, user_id, rrp_device_id, envelopes),
         {:ok, events} <- require_key_directory_events(params["workspace_key_directory_events"]),
         :ok <- validate_envelope_event_count(envelopes, events),
         {:ok, attrs_list} <-
           validate_member_envelopes(
             envelopes,
             events,
             params["workspace_key_directory_checkpoint"],
             workspace,
             workspace_id,
             user_id,
             rrp_device_id
           ) do
      case Encryption.save_member_envelopes_with_key_directory(
             workspace_id,
             attrs_list,
             events,
             params["workspace_key_directory_checkpoint"]
           ) do
        {:ok, _} ->
          json(conn, %{ok: true})

        {:error, :missing_key_directory} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "missing_key_directory"})

        {:error, :invalid_key_directory} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})

        {:error, reason} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: to_string(reason)})
      end
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  rescue
    ArgumentError ->
      conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})
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

  def get_member_envelope(conn, %{"workspace_id" => workspace_id}) do
    user_id = conn.assigns.current_user_id
    rrp_device_id = conn.assigns[:rrp_device_id]

    with :ok <- require_workspace_crypto_access(workspace_id, user_id, rrp_device_id),
         :ok <- reject_wipe_required_device(workspace_id, rrp_device_id) do
      send_member_envelope(conn, workspace_id, user_id)
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  defp send_member_envelope(conn, workspace_id, user_id) do
    case Encryption.get_member_envelope(workspace_id, user_id) do
      nil ->
        conn |> put_status(:not_found) |> json(%{error: "not_found"})

      envelope ->
        sender =
          if envelope.sender_device_id, do: Devices.get_device(envelope.sender_device_id)

        json(
          conn,
          %{
            key_version: envelope.key_version,
            sender_device_id: envelope.sender_device_id,
            workspace_key_directory_checkpoint: operation_checkpoint_envelope(envelope),
            workspace_key_directory_checkpoint_ancestry:
              Encryption.workspace_key_operation_checkpoint_ancestry(envelope),
            workspace_key_directory_event_ancestry:
              Encryption.workspace_key_operation_event_ancestry(envelope)
          }
          |> Map.merge(Encryption.member_envelope_response_fields(envelope))
          |> Map.merge(DeviceIdentity.sender_fields(sender))
        )
    end
  end

  defp reject_wipe_required_device(_workspace_id, nil), do: :ok

  defp reject_wipe_required_device(workspace_id, device_id) do
    if Workspaces.workspace_device_wipe_required?(workspace_id, device_id),
      do: {:error, :forbidden, "device_wipe_required"},
      else: :ok
  end

  # --- Private helpers ---

  defp fetch_workspace(workspace_id) do
    case Workspaces.get_workspace(workspace_id) do
      nil -> {:error, :not_found, "workspace_not_found"}
      workspace -> {:ok, workspace}
    end
  end

  defp require_workspace_crypto_access(workspace_id, user_id, device_id) do
    if Workspaces.guest_user?(user_id) do
      require_active_guest_device_access(workspace_id, user_id, device_id)
    else
      case Workspaces.get_member_role(workspace_id, user_id) do
        role when is_binary(role) and role != "guest" -> :ok
        _ -> {:error, :forbidden, "not_a_member"}
      end
    end
  end

  defp require_active_guest_device_access(workspace_id, user_id, device_id) do
    if Devices.user_owns_active_device?(user_id, device_id) and
         Workspaces.guest_user?(user_id) and
         Workspaces.authorize_workspace_guest_access(workspace_id, user_id) == :ok and
         Encryption.active_workspace_scope_guest_device_admitted?(
           workspace_id,
           user_id,
           device_id
         ) do
      :ok
    else
      {:error, :forbidden, "not_a_member"}
    end
  end

  defp require_member_envelope_authority(workspace, user_id, role) do
    if workspace.kek_rotation_initiator_user_id == user_id or role in ~w(owner admin) do
      :ok
    else
      {:error, :forbidden, "forbidden"}
    end
  end

  defp authorize_member_envelope_write(workspace, user_id, device_id) do
    if Workspaces.guest_user?(user_id) do
      require_workspace_scope_guest_device(workspace.id, user_id, device_id)
    else
      case Workspaces.get_member_role(workspace.id, user_id) do
        role when is_binary(role) and role != "guest" ->
          require_member_envelope_authority(workspace, user_id, role)

        _ ->
          {:error, :forbidden, "not_a_member"}
      end
    end
  end

  defp require_workspace_scope_guest_device(workspace_id, user_id, device_id) do
    if Devices.user_owns_active_device?(user_id, device_id) and
         Workspaces.guest_user?(user_id) and
         Workspaces.authorize_workspace_guest_access(workspace_id, user_id) == :ok and
         Encryption.active_workspace_scope_guest_device_admitted?(
           workspace_id,
           user_id,
           device_id
         ) do
      :ok
    else
      {:error, :forbidden, "not_a_member"}
    end
  end

  defp validate_guest_self_envelopes(workspace, user_id, device_id, envelopes) do
    if Workspaces.guest_user?(user_id) do
      valid? =
        Enum.all?(envelopes, fn envelope ->
          envelope["target_user_id"] == user_id and
            envelope["sender_device_id"] == device_id and
            envelope["key_version"] == workspace.current_kek_version
        end)

      if valid?, do: :ok, else: {:error, :forbidden, "forbidden"}
    else
      :ok
    end
  end

  defp require_envelopes(envelopes) when is_list(envelopes) and envelopes != [],
    do: {:ok, envelopes}

  defp require_envelopes(_), do: {:error, :bad_request, "envelopes_required"}

  defp require_key_directory_events(events) when is_list(events) and events != [],
    do: {:ok, events}

  defp require_key_directory_events(_),
    do: {:error, :unprocessable_entity, "missing_key_directory"}

  defp validate_envelope_event_count(envelopes, events) do
    if length(envelopes) == length(events) do
      :ok
    else
      {:error, :unprocessable_entity, "key_directory_event_count_mismatch"}
    end
  end

  defp validate_member_envelopes(
         envelopes,
         events,
         checkpoint,
         workspace,
         workspace_id,
         user_id,
         rrp_device_id
       ) do
    envelopes
    |> Enum.zip(events)
    |> Enum.reduce_while({:ok, []}, fn {env, event}, {:ok, acc} ->
      case validate_member_envelope(
             env,
             event,
             checkpoint,
             workspace,
             workspace_id,
             user_id,
             rrp_device_id
           ) do
        {:ok, attrs} -> {:cont, {:ok, [attrs | acc]}}
        {:error, status, error} -> {:halt, {:error, status, error}}
      end
    end)
    |> case do
      {:ok, attrs} -> {:ok, Enum.reverse(attrs)}
      error -> error
    end
  end

  defp validate_member_envelope(
         env,
         event,
         checkpoint,
         workspace,
         workspace_id,
         user_id,
         rrp_device_id
       ) do
    sender_device_id = env["sender_device_id"]
    target_user_id = env["target_user_id"]
    key_version = env["key_version"]

    with :ok <- validate_sender_device_match(rrp_device_id, sender_device_id),
         :ok <-
           require_target_envelope_recipient(
             workspace_id,
             user_id,
             rrp_device_id,
             target_user_id
           ),
         :ok <- validate_key_version_range(key_version, workspace, user_id),
         {:ok, sender_device} <- fetch_active_device(user_id, sender_device_id),
         {:ok, target_identity} <-
           fetch_target_identity(target_user_id, get_in(env, ["recipient", "encryption_key_id"])) do
      prepare_workspace_member_envelope(
        env,
        %{
          workspace_id: workspace_id,
          target_user_id: target_user_id,
          key_version: key_version,
          sender_device_id: sender_device_id
        },
        %{
          workspace_id: workspace_id,
          sender_user_id: user_id,
          target_identity: target_identity,
          sender_device: sender_device
        },
        event,
        checkpoint
      )
    end
  end

  defp validate_sender_device_match(nil, _sender_device_id), do: :ok

  defp validate_sender_device_match(rrp_device_id, sender_device_id) do
    if rrp_device_id == sender_device_id do
      :ok
    else
      {:error, :forbidden, "sender_device_id_mismatch"}
    end
  end

  defp require_target_envelope_recipient(
         workspace_id,
         actor_user_id,
         actor_device_id,
         target_user_id
       )
       when is_binary(target_user_id) do
    if Workspaces.guest_user?(target_user_id) do
      if target_user_id == actor_user_id do
        require_workspace_scope_guest_device(workspace_id, actor_user_id, actor_device_id)
      else
        {:error, :forbidden, "target_not_a_member"}
      end
    else
      case Workspaces.get_member_role(workspace_id, target_user_id) do
        role when is_binary(role) and role != "guest" -> :ok
        _ -> {:error, :forbidden, "target_not_a_member"}
      end
    end
  end

  defp require_target_envelope_recipient(_, _, _, _),
    do: {:error, :forbidden, "target_not_a_member"}

  defp validate_key_version_range(key_version, workspace, user_id) when is_integer(key_version) do
    max = max_allowed_key_version(workspace, user_id, key_version)

    cond do
      RotationPolicy.kek_overdue?(workspace) and
          key_version != workspace.current_kek_version + 1 ->
        {:error, :unprocessable_entity, "kek_rotation_required"}

      key_version < 1 ->
        {:error, :unprocessable_entity, "key_version_must_be_positive"}

      key_version < workspace.min_kek_version ->
        {:error, :unprocessable_entity, "key_version_below_minimum"}

      key_version > max ->
        {:error, :unprocessable_entity, "key_version_too_high"}

      true ->
        :ok
    end
  end

  defp validate_key_version_range(_key_version, _workspace, _user_id),
    do: {:error, :unprocessable_entity, "invalid_kek_version"}

  defp max_allowed_key_version(workspace, user_id, key_version) do
    if rotation_initiator_next_version?(workspace, user_id, key_version),
      do: workspace.current_kek_version + 1,
      else: workspace.current_kek_version
  end

  defp rotation_initiator_next_version?(workspace, user_id, key_version) do
    RotationPolicy.kek_overdue?(workspace) and
      workspace.kek_rotation_initiator_user_id == user_id and
      key_version == workspace.current_kek_version + 1
  end

  defp fetch_active_device(user_id, device_id) when is_binary(device_id) do
    case Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil, identity_wipe_required_at: nil} = device ->
        {:ok, device}

      _ ->
        {:error, :forbidden, "invalid_device"}
    end
  end

  defp fetch_active_device(_user_id, _device_id), do: {:error, :forbidden, "invalid_device"}

  defp fetch_target_identity(user_id, recipient_key_id)
       when is_binary(user_id) and is_binary(recipient_key_id) do
    current =
      case Encryption.user_identity_key_for_new_encryption(user_id) do
        {:ok, key} -> key
        {:error, _reason} -> nil
      end

    pending = Encryption.get_pending_user_identity_public_key(user_id)

    [current, pending]
    |> Enum.reject(&is_nil/1)
    |> Enum.find(&(&1.encryption_key_id == recipient_key_id))
    |> case do
      nil -> {:error, :unprocessable_entity, "target_identity_key_missing"}
      identity -> {:ok, identity}
    end
  end

  defp fetch_target_identity(_, _),
    do: {:error, :unprocessable_entity, "target_identity_key_missing"}

  defp prepare_workspace_member_envelope(env, metadata, validation_context, event, checkpoint) do
    case Encryption.prepare_workspace_member_envelope_from_client(
           env,
           metadata,
           validation_context,
           event,
           checkpoint
         ) do
      {:ok, attrs} ->
        {:ok, attrs}

      {:error, :invalid_workspace_member_kek_wrap} ->
        {:error, :unprocessable_entity, "invalid_workspace_member_kek_wrap"}
    end
  end

  defp operation_checkpoint_envelope(envelope),
    do: Encryption.member_envelope_operation_checkpoint_envelope(envelope)
end
