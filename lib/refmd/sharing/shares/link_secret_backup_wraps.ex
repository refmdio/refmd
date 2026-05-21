defmodule RefMD.Sharing.Shares.LinkSecretBackupWraps do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Devices
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireRBAC

  alias RefMD.Sharing.ShareLinkSecretBackupWrap

  @spec insert!(map(), map(), map()) :: :ok | no_return()
  def insert!(share, document, attrs) do
    expected_recipients = expected_recipients!(document.workspace_id)

    validate_coverage!(attrs.share_link_secret_backup_wraps, expected_recipients)

    Enum.each(attrs.share_link_secret_backup_wraps, fn wrap ->
      :ok = validate_wrap!(wrap, share, document, attrs, expected_recipients)

      %ShareLinkSecretBackupWrap{}
      |> ShareLinkSecretBackupWrap.changeset(%{
        share_id: share.id,
        recipient_user_id: get_in(wrap, ["resource", "recipient_user_id"]),
        recipient_device_id: get_in(wrap, ["resource", "recipient_device_id"]),
        recipient_encryption_key_id: get_in(wrap, ["resource", "recipient_encryption_key_id"]),
        wrap: wrap
      })
      |> Repo.insert!()
    end)

    :ok
  rescue
    _ -> Repo.rollback(:invalid_share_link_secret_backup_wrap)
  end

  defp validate_wrap!(wrap, share, document, attrs, expected_recipients) do
    resource = wrap["resource"]
    sender = wrap["sender"]

    sender_device = fetch_active_sender_device!(attrs, sender)

    expected_recipient =
      Map.fetch!(expected_recipients, Map.fetch!(resource, "recipient_device_id"))

    Encryption.validate_share_link_secret_backup_wrap(wrap, %{
      expected_resource: %{
        "workspace_id" => document.workspace_id,
        "share_id" => share.id,
        "token_hash" => attrs.token_hash,
        "scope_kind" => attrs.scope,
        "scope_id" => document.id,
        "permission" => attrs.permission,
        "password_protected" => attrs.password_protected,
        "created_event_hash" => attrs.created_event_hash,
        "share_capability_secret_commitment" => attrs.share_capability_secret_commitment,
        "password_capability_secret_commitment" => attrs.password_capability_secret_commitment,
        "workspace_pin_bootstrap_hash" => attrs.authenticated_workspace_pin_bootstrap_hash
      },
      expected_recipient: expected_recipient,
      sender_device: sender_device,
      key_directory_checkpoint_payload: attrs.key_directory_checkpoint["payload"],
      key_directory_events: attrs.key_directory_events
    })
  end

  defp expected_recipients!(workspace_id) do
    role_by_id =
      workspace_id
      |> Workspaces.list_workspace_roles()
      |> Map.new(&{&1.id, &1})

    query =
      from(d in RefMD.Devices.Device,
        join: wm in RefMD.Workspaces.WorkspaceMember,
        on: wm.user_id == d.user_id and wm.workspace_id == ^workspace_id,
        where: is_nil(d.revoked_at),
        select: %{
          user_id: d.user_id,
          device_id: d.id,
          encryption_key_id: d.encryption_key_id,
          role_id: wm.role_id
        }
      )

    query
    |> Repo.all()
    |> Enum.filter(fn recipient ->
      role = Map.fetch!(role_by_id, recipient.role_id)
      permissions = RequireRBAC.effective_permissions(role)

      MapSet.member?(permissions, "document:manage_share") or
        MapSet.member?(permissions, "workspace:admin")
    end)
    |> Map.new(&{&1.device_id, &1})
  end

  defp validate_coverage!(wraps, expected_recipients) do
    expected = MapSet.new(Map.keys(expected_recipients))

    actual =
      wraps
      |> Enum.map(&get_in(&1, ["resource", "recipient_device_id"]))
      |> MapSet.new()

    cond do
      MapSet.size(expected) == 0 ->
        raise ArgumentError, "share_link_secret_backup_recipient_required"

      MapSet.size(actual) != length(wraps) ->
        raise ArgumentError, "share_link_secret_backup_duplicate_recipient"

      actual != expected ->
        raise ArgumentError, "share_link_secret_backup_coverage_invalid"

      true ->
        :ok
    end
  end

  defp fetch_active_sender_device!(attrs, sender) do
    sender_device_id = sender["device_id"]

    case Devices.get_device(sender_device_id) do
      %{revoked_at: nil} = device ->
        cond do
          device.user_id != attrs.created_by or sender_device_id != attrs.actor_device_id ->
            raise ArgumentError, "share_link_secret_backup_sender_invalid"

          sender["user_id"] != attrs.created_by ->
            raise ArgumentError, "share_link_secret_backup_sender_invalid"

          sender["signing_key_id"] != device.signing_key_id ->
            raise ArgumentError, "share_link_secret_backup_sender_key_invalid"

          true ->
            device
        end

      _ ->
        raise ArgumentError, "share_link_secret_backup_sender_invalid"
    end
  end
end
