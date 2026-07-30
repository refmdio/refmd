defmodule RefMD.Encryption.KeyDirectory.Authority do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Encryption.KeyDirectory.{Event, Protocol}
  alias RefMD.Repo

  def empty_state,
    do: %{
      members: %{},
      invitations: %{},
      guest_grants: %{},
      shares: %{},
      rotations: %{},
      key_owners: %{},
      self_removed_members: MapSet.new()
    }

  def assert_event_authority!(payload) do
    payload
    |> stored_authority_state()
    |> assert_event_authority!(payload)
  end

  def assert_workspace_pin_bootstrap_issuer_authority!(
        workspace_id,
        event_head_sequence,
        %{"signer_kind" => "device", "user_id" => user_id}
      )
      when is_binary(workspace_id) and is_integer(event_head_sequence) and
             event_head_sequence >= 0 and
             is_binary(user_id) do
    state = workspace_authority_state(workspace_id, event_head_sequence)
    role = Map.get(state.members, user_id)

    if permission_granted?(role, :workspace_admin) or
         permission_granted?(role, :document_manage_share) do
      :ok
    else
      raise ArgumentError, "workspace_pin_issuer_authority_invalid"
    end
  end

  def assert_workspace_pin_bootstrap_issuer_authority!(_, _, _),
    do: raise(ArgumentError, "workspace_pin_issuer_authority_invalid")

  def assert_workspace_admin_authority!(
        workspace_id,
        event_head_sequence,
        %{"signer_kind" => "device", "user_id" => user_id}
      )
      when is_binary(workspace_id) and is_integer(event_head_sequence) and
             event_head_sequence >= 0 and
             is_binary(user_id) do
    state = workspace_authority_state(workspace_id, event_head_sequence)
    role = Map.get(state.members, user_id)

    if permission_granted?(role, :workspace_admin) do
      :ok
    else
      raise ArgumentError, "workspace_admin_authority_invalid"
    end
  end

  def assert_workspace_admin_authority!(_, _, _),
    do: raise(ArgumentError, "workspace_admin_authority_invalid")

  @audit_workspace_admin_events ~w(
    workspace.member.added
    workspace.member.removed
    workspace.member.role_changed
    workspace.invitation.created
    workspace.invitation.revoked
    workspace.guest_invitation.created
    workspace.guest_invitation.revoked
    workspace.guest_grant.revoked
    workspace.guest_device.revoked
    workspace.kek.rotation_started
    workspace.kek.rotation_completed
    workspace.kek.old_key_deleted
    workspace.suite_policy.changed
  )

  @audit_share_management_events ~w(
    workspace.share.created
    workspace.share.metadata_updated
    workspace.share.key_scope_added
    workspace.share.key_scope_replaced
    workspace.share.key_scope_removed
    workspace.share.exclusion_changed
    workspace.share.revoked
  )

  @audit_document_rotation_events ~w(
    workspace.dek.rotation_started
    workspace.dek.rotation_completed
    workspace.dek.old_key_deleted
  )

  @audit_active_member_events ~w(
    workspace.security_device_revocation.applied
    workspace.identity_self_envelope_rewrap.completed
  )

  def assert_audit_checkpoint_authority!(
        workspace_id,
        event_head_sequence,
        event_type,
        %{"signer_kind" => "device", "user_id" => user_id}
      ) do
    assert_audit_authority_inputs!(workspace_id, event_head_sequence, event_type, user_id)
    state = workspace_authority_state(workspace_id, event_head_sequence)
    role = Map.get(state.members, user_id)

    authorized? =
      case audit_authority_kind(event_type) do
        :workspace_admin ->
          permission_granted?(role, :workspace_admin)

        :share_management ->
          permission_granted?(role, :document_manage_share) or
            permission_granted?(role, :workspace_admin)

        :document_rotation ->
          permission_granted?(role, :document_archive)

        :active_member ->
          permission_granted?(role, :active_member)

        :unknown ->
          false
      end

    if authorized?, do: :ok, else: raise(ArgumentError, "audit_checkpoint_authority_unverified")
  end

  def assert_audit_checkpoint_authority!(_, _, _, _),
    do: raise(ArgumentError, "audit_checkpoint_authority_unverified")

  defp assert_audit_authority_inputs!(workspace_id, event_head_sequence, event_type, user_id)
       when is_binary(workspace_id) and is_integer(event_head_sequence) and
              event_head_sequence >= 0 and is_binary(event_type) and is_binary(user_id),
       do: :ok

  defp assert_audit_authority_inputs!(_, _, _, _),
    do: raise(ArgumentError, "audit_checkpoint_authority_unverified")

  defp audit_authority_kind(event_type) do
    cond do
      event_type in @audit_workspace_admin_events -> :workspace_admin
      event_type in @audit_share_management_events -> :share_management
      event_type in @audit_document_rotation_events -> :document_rotation
      event_type in @audit_active_member_events -> :active_member
      true -> :unknown
    end
  end

  def active_workspace_scope_guest_device_admitted?(
        workspace_id,
        event_head_sequence,
        user_id,
        device_id
      )
      when is_binary(workspace_id) and is_integer(event_head_sequence) and
             event_head_sequence >= 0 and is_binary(user_id) and is_binary(device_id) do
    workspace_id
    |> workspace_authority_state(event_head_sequence)
    |> workspace_scope_guest_device_admitted?(user_id, device_id)
  end

  def active_workspace_scope_guest_device_admitted?(_, _, _, _), do: false

  def stored_authority_state(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => sequence
      }) do
    workspace_id
    |> workspace_events_before(sequence)
    |> Enum.reduce(empty_state(), &apply_authority_event/2)
  end

  def stored_authority_state(_payload), do: empty_state()

  def assert_and_apply_event!(state, payload) do
    assert_event_authority!(state, payload)
    apply_authority_event(%{event_type: payload["event_type"], payload: payload}, state)
  end

  def assert_event_authority!(
        state,
        %{
          "scope_kind" => "workspace",
          "event_type" => event_type,
          "actor" => %{"signer_kind" => "share_participant_device"},
          "body" => body
        }
      )
      when event_type in [
             "document_write_session_admitted",
             "document_snapshot_accepted"
           ] do
    assert_share_participant_document_admission!(state, body)
  end

  def assert_event_authority!(
        state,
        %{
          "scope_kind" => "workspace",
          "event_type" => event_type,
          "actor" => actor
        } = payload
      ) do
    permission = required_permission!(event_type)

    authorized? = event_authorized?(state, payload, actor, permission)

    unless authorized?, do: raise(ArgumentError, authority_error(payload, permission))

    assert_event_transition!(state, payload)
  end

  def assert_event_authority!(_state, _payload), do: :ok

  defp event_authorized?(state, payload, actor, permission) do
    [
      fn -> permission == :none end,
      fn -> initial_owner_member_added?(state, payload) end,
      fn -> initial_workspace_bootstrap_key_event?(state, payload) end,
      fn -> self_member_removal_authorized?(state, payload) end,
      fn -> identity_device_key_add_authorized?(state, payload, actor, permission) end,
      fn -> guest_identity_key_add_authorized?(state, payload, actor, permission) end,
      fn -> guest_identity_wrap_authorized?(state, payload, actor, permission) end,
      fn -> permission_granted?(Map.get(state.members, actor_user_id!(actor)), permission) end,
      fn -> self_member_key_revocation_authorized?(state, payload) end,
      fn -> guest_grant_permission_granted?(state, actor, payload, permission) end
    ]
    |> Enum.any?(& &1.())
  end

  defp identity_device_key_add_authorized?(
         state,
         %{"event_type" => "device_key_added"},
         %{"signer_kind" => "identity", "user_id" => user_id},
         :active_member
       )
       when is_binary(user_id) do
    permission_granted?(Map.get(state.members, user_id), :active_member)
  end

  defp identity_device_key_add_authorized?(_, _, _, _), do: false

  defp guest_identity_key_add_authorized?(
         state,
         %{"event_type" => "identity_key_added"},
         %{"signer_kind" => "device", "user_id" => user_id, "device_id" => device_id},
         :active_member
       )
       when is_binary(user_id) and is_binary(device_id) do
    workspace_scope_guest_device_admitted?(state, user_id, device_id)
  end

  defp guest_identity_key_add_authorized?(_, _, _, _), do: false

  defp guest_identity_wrap_authorized?(
         state,
         %{
           "scope_kind" => "workspace",
           "scope_id" => workspace_id,
           "event_type" => "wrap_issued",
           "body" => %{
             "purpose" => "workspace_member_kek_wrap",
             "resource" => %{
               "workspace_id" => workspace_id,
               "target_user_id" => user_id
             },
             "recipient" => %{
               "recipient_kind" => "user_identity",
               "user_id" => user_id
             },
             "sender" => %{"user_id" => user_id, "device_id" => device_id}
           }
         },
         %{"signer_kind" => "device", "user_id" => user_id, "device_id" => device_id},
         :active_member
       )
       when is_binary(workspace_id) and is_binary(user_id) and is_binary(device_id) do
    workspace_scope_guest_device_admitted?(state, user_id, device_id)
  end

  defp guest_identity_wrap_authorized?(_, _, _, _), do: false

  defp workspace_scope_guest_device_admitted?(%{guest_grants: guest_grants}, user_id, device_id) do
    Enum.any?(guest_grants, fn
      {_grant_id,
       %{
         guest_user_id: ^user_id,
         guest_device_id: ^device_id,
         scope_kind: "workspace",
         scope_id: "none",
         status: "active"
       }} ->
        true

      _entry ->
        false
    end)
  end

  defp required_permission!(event_type)
       when event_type in [
              "member_added",
              "member_role_changed",
              "member_removed",
              "suite_policy_changed",
              "workspace_invitation_created",
              "workspace_invitation_bootstrap_updated",
              "workspace_invitation_revoked",
              "guest_invitation_created",
              "guest_invitation_bootstrap_updated",
              "guest_invitation_revoked",
              "rotation_started",
              "rotation_completed",
              "old_key_deleted"
            ],
       do: :workspace_admin

  defp required_permission!(event_type)
       when event_type in [
              "share_created",
              "share_revoked",
              "share_metadata_updated",
              "share_key_scope_added",
              "share_key_scope_replaced",
              "share_key_scope_removed",
              "share_exclusion_changed",
              "recipient_bound_delivery_admitted"
            ],
       do: :document_manage_share

  defp required_permission!(event_type)
       when event_type in [
              "identity_key_added",
              "device_key_added",
              "signing_key_revoked",
              "encryption_key_revoked",
              "wrap_issued",
              "workspace_member_envelope_issued"
            ],
       do: :active_member

  defp required_permission!(event_type)
       when event_type in [
              "workspace_invitation_redeemed",
              "guest_invitation_redeemed",
              "guest_grant_revoked",
              "guest_device_revoked"
            ],
       do: :none

  defp required_permission!(event_type)
       when event_type in [
              "document_write_session_admitted",
              "document_snapshot_accepted"
            ],
       do: :document_write

  defp required_permission!("document_write_state_changed"), do: :document_archive

  defp required_permission!(event_type),
    do: raise(ArgumentError, "key_directory_event_authority_unknown:#{event_type}")

  defp actor_user_id!(%{"signer_kind" => "device", "user_id" => user_id}) when is_binary(user_id),
    do: user_id

  defp actor_user_id!(_actor), do: raise(ArgumentError, "key_directory_actor_authority_invalid")

  defp workspace_events_before(workspace_id, sequence) do
    Event
    |> where(
      [e],
      e.scope_kind == "workspace" and e.scope_id == ^workspace_id and e.sequence < ^sequence
    )
    |> order_by([e], asc: e.sequence)
    |> select([e], %{event_type: e.event_type, payload: e.payload})
    |> Repo.all()
  end

  defp workspace_authority_state(workspace_id, event_head_sequence) do
    workspace_id
    |> workspace_events_before(event_head_sequence + 1)
    |> Enum.reduce(empty_state(), &apply_authority_event/2)
  end

  defp apply_authority_event(%{event_type: "member_added", payload: %{"body" => body}}, state) do
    put_member_role(state, body["user_id"], body["base_role"])
  end

  defp apply_authority_event(
         %{event_type: "member_role_changed", payload: %{"body" => body}},
         state
       ) do
    put_member_role(state, body["user_id"], body["new_base_role"])
  end

  defp apply_authority_event(
         %{event_type: "workspace_invitation_created", payload: %{"body" => body}},
         state
       ) do
    put_in(state, [:invitations, body["invitation_id"]], body["base_role"])
  end

  defp apply_authority_event(
         %{event_type: "workspace_invitation_redeemed", payload: %{"body" => body}},
         state
       ) do
    role = get_in(state, [:invitations, body["invitation_id"]])

    state
    |> put_member_role(body["redeemed_user_id"], role)
    |> put_key_owner(body["redeemed_encryption_key_id"], %{
      user_id: body["redeemed_user_id"],
      device_id: body["redeemed_device_id"]
    })
  end

  defp apply_authority_event(
         %{event_type: "guest_invitation_redeemed", payload: %{"body" => body}},
         state
       ) do
    put_in(state, [:guest_grants, body["guest_grant_id"]], %{
      guest_grant_id: body["guest_grant_id"],
      guest_user_id: body["guest_user_id"],
      guest_device_id: body["guest_device_id"],
      scope_kind: body["scope_kind"],
      scope_id: body["scope_id"],
      permission: body["permission"],
      status: "active"
    })
  end

  defp apply_authority_event(
         %{event_type: "guest_grant_revoked", payload: %{"body" => body}},
         state
       ) do
    update_in(state, [:guest_grants, body["guest_grant_id"]], fn
      nil -> nil
      grant -> %{grant | status: "revoked"}
    end)
  end

  defp apply_authority_event(
         %{event_type: "guest_device_revoked", payload: %{"body" => body}},
         state
       ) do
    revoked_user_id = body["guest_user_id"]
    revoked_device_id = body["guest_device_id"]

    update_in(state, [:guest_grants], fn guest_grants ->
      Map.new(guest_grants, fn
        {grant_id, %{guest_user_id: user_id, guest_device_id: device_id} = grant}
        when user_id == revoked_user_id and device_id == revoked_device_id ->
          {grant_id, %{grant | status: "revoked"}}

        entry ->
          entry
      end)
    end)
  end

  defp apply_authority_event(
         %{event_type: "member_removed", payload: %{"actor" => actor, "body" => body}},
         state
       ) do
    user_id = body["user_id"]

    state
    |> update_in([:members], &Map.delete(&1, user_id))
    |> maybe_put_self_removed_member(actor, user_id)
  end

  defp apply_authority_event(
         %{event_type: "rotation_started", payload: %{"body" => body} = payload},
         state
       ) do
    put_rotation_state(state, body, %{
      status: :started,
      new_key_version: body["new_key_version"],
      started_event_hash: Protocol.event_hash(payload)
    })
  end

  defp apply_authority_event(
         %{event_type: "rotation_completed", payload: %{"body" => body} = payload},
         state
       ) do
    update_rotation_state(state, body, fn rotation ->
      rotation
      |> Map.put(:status, :completed)
      |> Map.put(:new_key_version, body["new_key_version"])
      |> Map.put(:completed_event_hash, Protocol.event_hash(payload))
    end)
  end

  defp apply_authority_event(%{event_type: "old_key_deleted", payload: %{"body" => body}}, state) do
    update_rotation_state(state, body, &Map.put(&1, :status, :deleted))
  end

  defp apply_authority_event(
         %{event_type: "device_key_added", payload: %{"body" => body}},
         state
       ) do
    owner = %{user_id: body["user_id"], device_id: body["device_id"]}

    state
    |> put_key_owner(body["signing_key_id"], owner)
    |> put_key_owner(body["encryption_key_id"], owner)
  end

  defp apply_authority_event(%{event_type: "share_created", payload: %{"body" => body}}, state) do
    put_in(state, [:shares, body["share_id"]], %{
      share_id: body["share_id"],
      parent_share_id: nil,
      scope_kind: body["scope_kind"],
      scope_id: body["scope_id"],
      permission: body["permission"],
      status: "active",
      removed_scope_ids: MapSet.new()
    })
  end

  defp apply_authority_event(%{event_type: "share_revoked", payload: %{"body" => body}}, state) do
    update_in(state, [:shares, body["share_id"]], fn
      nil -> nil
      share -> %{share | status: "revoked"}
    end)
  end

  defp apply_authority_event(
         %{event_type: "share_key_scope_added", payload: %{"body" => body}},
         state
       ) do
    parent_share = Map.get(state.shares, body["parent_share_id"], %{})

    put_in(state, [:shares, body["share_id"]], %{
      share_id: body["share_id"],
      parent_share_id: body["parent_share_id"],
      scope_kind: body["scope_kind"],
      scope_id: body["scope_id"],
      permission: Map.get(parent_share, :permission),
      status: "active",
      removed_scope_ids: MapSet.new()
    })
  end

  defp apply_authority_event(
         %{event_type: "share_key_scope_replaced", payload: %{"body" => body}},
         state
       ) do
    existing_share = Map.get(state.shares, body["share_id"], %{})

    put_in(state, [:shares, body["share_id"]], %{
      share_id: body["share_id"],
      parent_share_id: Map.get(existing_share, :parent_share_id),
      scope_kind: body["scope_kind"],
      scope_id: body["scope_id"],
      permission: Map.get(existing_share, :permission),
      status: "active",
      removed_scope_ids: Map.get(existing_share, :removed_scope_ids, MapSet.new())
    })
  end

  defp apply_authority_event(
         %{event_type: "share_key_scope_removed", payload: %{"body" => body}},
         state
       ) do
    update_in(state, [:shares, body["share_id"]], fn
      nil -> nil
      share -> mark_share_scope_removed(share, body["scope_id"])
    end)
  end

  defp apply_authority_event(_event, state), do: state

  defp put_member_role(state, user_id, role) when is_binary(user_id) and is_binary(role),
    do: put_in(state, [:members, user_id], role)

  defp put_member_role(state, _user_id, _role), do: state

  defp put_key_owner(state, key_id, %{user_id: user_id, device_id: device_id})
       when is_binary(key_id) and is_binary(user_id) and is_binary(device_id) do
    Map.update(state, :key_owners, %{key_id => %{user_id: user_id, device_id: device_id}}, fn
      key_owners -> Map.put(key_owners, key_id, %{user_id: user_id, device_id: device_id})
    end)
  end

  defp put_key_owner(state, _key_id, _owner), do: state

  defp maybe_put_self_removed_member(
         state,
         %{"signer_kind" => "device", "user_id" => user_id},
         user_id
       )
       when is_binary(user_id) do
    Map.update(state, :self_removed_members, MapSet.new([user_id]), fn self_removed_members ->
      MapSet.put(self_removed_members, user_id)
    end)
  end

  defp maybe_put_self_removed_member(state, _actor, _user_id), do: state

  defp permission_granted?(role, :workspace_admin),
    do: role_permission_granted?(role, "workspace:admin")

  defp permission_granted?(role, :document_manage_share),
    do: role_permission_granted?(role, "document:manage_share")

  defp permission_granted?(role, :document_write),
    do: role_permission_granted?(role, "document:write")

  defp permission_granted?(role, :document_archive),
    do: role_permission_granted?(role, "document:archive")

  defp permission_granted?(%{base_role: role}, :active_member), do: is_binary(role)
  defp permission_granted?(role, :active_member), do: is_binary(role)

  defp permission_granted?(_role, :none), do: true

  defp role_permission_granted?("owner", _permission), do: true

  defp role_permission_granted?(%{permissions: %MapSet{} = permissions}, permission),
    do: MapSet.member?(permissions, permission)

  defp role_permission_granted?(role, permission) when is_binary(role),
    do: permission in base_role_permissions(role)

  defp role_permission_granted?(_role, _permission), do: false

  defp base_role_permissions("admin"),
    do:
      ~w(document:read document:write document:manage_share document:delete document:archive workspace:update workspace:features workspace:admin member:list member:invite guest:invite member:change_role member:remove role:manage)

  defp base_role_permissions("editor"),
    do: ~w(document:read document:write document:manage_share document:archive member:list)

  defp base_role_permissions("viewer"), do: ~w(document:read member:list)
  defp base_role_permissions("guest"), do: ~w(document:read)
  defp base_role_permissions(_), do: []

  defp guest_grant_permission_granted?(
         %{guest_grants: guest_grants},
         %{"signer_kind" => "device", "user_id" => user_id, "device_id" => device_id},
         %{"body" => %{"document_id" => document_id}},
         :document_write
       ) do
    Enum.any?(guest_grants, fn
      {_grant_id,
       %{
         guest_user_id: ^user_id,
         guest_device_id: ^device_id,
         permission: "edit",
         status: "active"
       } = grant} ->
        guest_grant_covers_document?(grant, document_id)

      _entry ->
        false
    end)
  end

  defp guest_grant_permission_granted?(_state, _actor, _payload, _permission), do: false

  defp guest_grant_covers_document?(%{scope_kind: "workspace"}, _document_id), do: true
  defp guest_grant_covers_document?(%{scope_id: document_id}, document_id), do: true
  defp guest_grant_covers_document?(_grant, _document_id), do: false

  defp self_member_removal_authorized?(
         state,
         %{
           "event_type" => "member_removed",
           "actor" => %{"signer_kind" => "device", "user_id" => user_id},
           "body" => %{"user_id" => user_id}
         }
       )
       when is_binary(user_id) do
    permission_granted?(Map.get(state.members, user_id), :active_member)
  end

  defp self_member_removal_authorized?(_state, _payload), do: false

  defp self_member_key_revocation_authorized?(
         state,
         %{
           "event_type" => event_type,
           "actor" => %{
             "signer_kind" => "device",
             "user_id" => user_id,
             "signing_key_id" => actor_signing_key_id
           },
           "body" => %{"key_id" => key_id, "reason" => "member_removed"}
         }
       )
       when event_type in ["signing_key_revoked", "encryption_key_revoked"] and
              is_binary(user_id) and is_binary(key_id) do
    self_removed? =
      state
      |> Map.get(:self_removed_members, MapSet.new())
      |> MapSet.member?(user_id)

    key_owner = Map.get(Map.get(state, :key_owners, %{}), key_id)

    self_removed? and (key_id == actor_signing_key_id or match?(%{user_id: ^user_id}, key_owner))
  end

  defp self_member_key_revocation_authorized?(_state, _payload), do: false

  defp assert_event_transition!(state, %{"event_type" => "rotation_started", "body" => body}) do
    if Map.has_key?(Map.get(state, :rotations, %{}), rotation_key(body)) do
      raise ArgumentError, "rotation_already_recorded"
    end

    :ok
  end

  defp assert_event_transition!(state, %{"event_type" => "rotation_completed", "body" => body}) do
    rotation = Map.get(Map.get(state, :rotations, %{}), rotation_key(body))

    cond do
      is_nil(rotation) ->
        raise ArgumentError, "rotation_started_event_missing"

      rotation.status != :started ->
        raise ArgumentError, "rotation_not_in_progress"

      rotation.new_key_version != body["new_key_version"] ->
        raise ArgumentError, "rotation_key_version_mismatch"

      true ->
        :ok
    end
  end

  defp assert_event_transition!(state, %{"event_type" => "old_key_deleted", "body" => body}) do
    rotation = Map.get(Map.get(state, :rotations, %{}), rotation_key(body))

    if is_nil(rotation) or rotation.status != :completed do
      raise ArgumentError, "rotation_completed_event_missing"
    end

    :ok
  end

  defp assert_event_transition!(
         _state,
         %{
           "event_type" => "member_role_changed",
           "actor" => %{"signer_kind" => "device", "user_id" => user_id},
           "body" => %{"user_id" => user_id, "new_base_role" => base_role}
         }
       ) do
    unless base_role in ["owner", "admin"] do
      raise ArgumentError, "member_role_change_candidate_signer_ineligible"
    end

    :ok
  end

  defp assert_event_transition!(_state, _payload), do: :ok

  defp put_rotation_state(state, body, rotation) do
    Map.update(state, :rotations, %{rotation_key(body) => rotation}, fn rotations ->
      Map.put(rotations, rotation_key(body), rotation)
    end)
  end

  defp update_rotation_state(state, body, update) do
    Map.update(state, :rotations, %{rotation_key(body) => update.(%{})}, fn rotations ->
      Map.update(rotations, rotation_key(body), update.(%{}), update)
    end)
  end

  defp rotation_key(body) do
    {body["rotation_kind"], body["scope_kind"], body["scope_id"], body["old_key_version"]}
  end

  defp mark_share_scope_removed(%{scope_id: scope_id} = share, scope_id),
    do: %{share | status: "removed"}

  defp mark_share_scope_removed(share, scope_id) do
    Map.update(share, :removed_scope_ids, MapSet.new([scope_id]), &MapSet.put(&1, scope_id))
  end

  defp initial_owner_member_added?(
         %{members: members},
         %{
           "event_type" => "member_added",
           "actor" => %{"signer_kind" => "device", "user_id" => user_id},
           "body" => %{"user_id" => user_id, "base_role" => "owner"}
         }
       ) do
    map_size(members) == 0
  end

  defp initial_owner_member_added?(_state, _payload), do: false

  defp initial_workspace_bootstrap_key_event?(
         %{members: members},
         %{
           "event_type" => event_type,
           "scope_kind" => "workspace",
           "actor" => %{"signer_kind" => "device"}
         }
       )
       when event_type in ["identity_key_added", "device_key_added"] do
    map_size(members) == 0
  end

  defp initial_workspace_bootstrap_key_event?(_state, _payload), do: false

  defp authority_error(_payload, :workspace_admin), do: "key_directory_workspace_admin_required"

  defp authority_error(_payload, :document_manage_share),
    do: "key_directory_manage_share_required"

  defp authority_error(_payload, :document_write), do: "key_directory_document_write_required"

  defp authority_error(_payload, :document_archive), do: "key_directory_document_archive_required"

  defp authority_error(_payload, :active_member), do: "key_directory_active_member_required"

  defp assert_share_participant_document_admission!(%{shares: shares}, body) do
    share = Map.get(shares, body["share_id"])

    cond do
      body["share_authority_kind"] != "share_participant_device" ->
        raise ArgumentError, "key_directory_share_participant_authority_required"

      body["share_permission"] != "edit" ->
        raise ArgumentError, "key_directory_share_participant_edit_required"

      is_nil(share) or share.status != "active" ->
        raise ArgumentError, "key_directory_share_participant_share_inactive"

      share.permission != "edit" ->
        raise ArgumentError, "key_directory_share_participant_edit_required"

      share_scope_removed?(share, body["document_id"]) ->
        raise ArgumentError, "key_directory_share_scope_not_active"

      not share_covers_document?(shares, share, body["document_id"]) ->
        raise ArgumentError, "key_directory_share_participant_scope_mismatch"

      true ->
        :ok
    end
  end

  defp share_covers_document?(shares, share, document_id),
    do: share_covers_document?(shares, share, document_id, [])

  defp share_covers_document?(_shares, %{scope_id: document_id}, document_id, _visited),
    do: true

  defp share_covers_document?(
         shares,
         %{share_id: share_id, scope_kind: "folder", scope_id: folder_id},
         document_id,
         visited
       )
       when is_binary(folder_id) and is_binary(document_id) do
    if share_id in visited do
      false
    else
      visited = [share_id | visited]

      document_descendant_of?(document_id, folder_id) or
        active_child_share_covers_document?(shares, share_id, document_id, visited)
    end
  end

  defp share_covers_document?(shares, %{share_id: share_id}, document_id, visited) do
    if share_id in visited do
      false
    else
      active_child_share_covers_document?(
        shares,
        share_id,
        document_id,
        [share_id | visited]
      )
    end
  end

  defp share_covers_document?(_shares, _share, _document_id, _visited), do: false

  defp active_child_share_covers_document?(_shares, nil, _document_id, _visited), do: false

  defp active_child_share_covers_document?(shares, share_id, document_id, visited) do
    Enum.any?(shares, fn
      {_child_share_id,
       %{
         parent_share_id: ^share_id,
         status: "active"
       } = child_share} ->
        not share_scope_removed?(child_share, document_id) and
          share_covers_document?(shares, child_share, document_id, visited)

      _entry ->
        false
    end)
  end

  defp document_descendant_of?(document_id, ancestor_id) do
    sql = """
    WITH RECURSIVE ancestors AS (
      SELECT id, parent_id
      FROM documents
      WHERE id = $1
      UNION ALL
      SELECT d.id, d.parent_id
      FROM documents d
      INNER JOIN ancestors a ON d.id = a.parent_id
    )
    SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $2)
    """

    case Repo.query(sql, [Ecto.UUID.dump!(document_id), Ecto.UUID.dump!(ancestor_id)]) do
      {:ok, %{rows: [[value]]}} -> value == true
      _ -> false
    end
  end

  defp share_scope_removed?(share, document_id) do
    share
    |> Map.get(:removed_scope_ids, MapSet.new())
    |> MapSet.member?(document_id)
  end
end
