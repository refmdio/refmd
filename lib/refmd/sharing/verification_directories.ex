defmodule RefMD.Sharing.VerificationDirectories do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.DocumentSignerKey
  alias RefMD.Repo

  alias RefMD.Sharing.{
    Share,
    ShareMount,
    ShareParticipantDevice,
    ShareParticipantPrincipal
  }

  @spec verification_directory(Ecto.UUID.t(), Ecto.UUID.t()) :: map()
  def verification_directory(share_id, document_id) do
    %{
      workspace_devices:
        (list_workspace_devices(document_id) ++ list_historical_workspace_devices(document_id))
        |> Enum.uniq_by(& &1.signing_public_key),
      share_participant_devices:
        (list_share_participant_devices(share_id) ++
           (document_id
            |> list_historical_share_participant_devices(share_id)
            |> Enum.map(&encode_verification_device/1)))
        |> Enum.uniq_by(& &1.signing_public_key)
    }
  end

  @spec document_share_participant_verification_directory(Ecto.UUID.t()) :: map()
  def document_share_participant_verification_directory(document_id) do
    %{
      workspace_devices: list_historical_workspace_devices(document_id),
      share_participant_devices:
        list_document_share_participant_devices(document_id)
        |> Enum.uniq_by(& &1.signing_public_key)
    }
  end

  defp list_workspace_devices(document_id) do
    from(d in RefMD.Devices.Device,
      join: wm in RefMD.Workspaces.WorkspaceMember,
      on: wm.user_id == d.user_id,
      join: doc in RefMD.Documents.Document,
      on: doc.workspace_id == wm.workspace_id,
      where: doc.id == ^document_id and is_nil(d.revoked_at),
      select: %{
        device_id: d.id,
        user_id: d.user_id,
        signing_public_key: d.signing_public_key,
        encryption_public_key: d.ecdh_public_key,
        historical: false
      }
    )
    |> Repo.all()
    |> Enum.map(fn device ->
      %{
        device
        | signing_public_key: Base.url_encode64(device.signing_public_key, padding: false),
          encryption_public_key: Base.url_encode64(device.encryption_public_key, padding: false)
      }
    end)
  end

  defp list_historical_workspace_devices(document_id) do
    from(k in DocumentSignerKey,
      where: k.document_id == ^document_id and k.signer_kind == "workspace",
      select: %{
        device_id: k.device_id,
        user_id: k.user_id,
        signing_public_key: k.signing_public_key,
        encryption_public_key: k.encryption_public_key,
        historical: true
      }
    )
    |> Repo.all()
    |> Enum.map(&encode_workspace_verification_device/1)
  end

  defp encode_workspace_verification_device(device) do
    %{
      device
      | signing_public_key: Base.url_encode64(device.signing_public_key, padding: false),
        encryption_public_key: Base.url_encode64(device.encryption_public_key, padding: false)
    }
  end

  defp list_share_participant_devices(share_id) do
    participant_devices =
      from(d in ShareParticipantDevice,
        join: p in ShareParticipantPrincipal,
        on: p.id == d.principal_id,
        where: d.share_id == ^share_id,
        select: %{
          share_id: d.share_id,
          device_id: d.id,
          principal_id: p.id,
          display_name: p.display_name,
          signing_public_key: d.signing_public_key,
          encryption_public_key: d.encryption_public_key,
          historical: false
        }
      )
      |> Repo.all()

    (participant_devices ++ list_mounted_share_devices([share_id]))
    |> Enum.uniq_by(&{&1.share_id, &1.device_id, &1.principal_id})
    |> Enum.map(&encode_verification_device/1)
  end

  defp list_mounted_share_devices(share_ids) do
    from(d in RefMD.Devices.Device,
      join: m in ShareMount,
      on: m.user_id == d.user_id,
      join: u in RefMD.Users.User,
      on: u.id == d.user_id,
      where: m.share_id in ^share_ids and is_nil(d.revoked_at),
      select: %{
        share_id: m.share_id,
        device_id: d.id,
        principal_id: d.user_id,
        display_name: u.name,
        signing_public_key: d.signing_public_key,
        encryption_public_key: d.ecdh_public_key,
        historical: false
      }
    )
    |> Repo.all()
  end

  defp encode_verification_device(device) do
    %{
      device
      | signing_public_key: Base.url_encode64(device.signing_public_key, padding: false),
        encryption_public_key: Base.url_encode64(device.encryption_public_key, padding: false)
    }
  end

  defp list_direct_share_participant_devices(share_ids) do
    from(d in ShareParticipantDevice,
      join: p in ShareParticipantPrincipal,
      on: p.id == d.principal_id,
      where: d.share_id in ^share_ids,
      select: %{
        share_id: d.share_id,
        device_id: d.id,
        principal_id: p.id,
        display_name: p.display_name,
        signing_public_key: d.signing_public_key,
        encryption_public_key: d.encryption_public_key,
        historical: false
      }
    )
    |> Repo.all()
  end

  defp list_historical_share_participant_devices(document_id, fallback_share_id) do
    from(k in DocumentSignerKey,
      where:
        k.document_id == ^document_id and
          k.signer_kind in ["share_participant", "mounted_share"],
      select: %{
        share_id: coalesce(k.share_id, type(^fallback_share_id, :binary_id)),
        device_id: k.device_id,
        principal_id: coalesce(k.principal_id, k.user_id),
        display_name: nil,
        signing_public_key: k.signing_public_key,
        encryption_public_key: k.encryption_public_key,
        historical: true
      }
    )
    |> Repo.all()
  end

  defp list_document_share_participant_devices(document_id) do
    share_ids =
      from(s in Share,
        left_join: child in Share,
        on: child.parent_share_id == s.id and child.document_id == ^document_id,
        where:
          s.permission == "edit" and
            ((is_nil(s.parent_share_id) and s.scope == "document" and
                s.document_id == ^document_id) or
               (is_nil(s.parent_share_id) and s.scope == "folder" and not is_nil(child.id))),
        select: s.id
      )

    root_share_ids = Repo.all(share_ids)

    (list_direct_share_participant_devices(root_share_ids) ++
       list_mounted_share_devices(root_share_ids) ++
       list_historical_share_participant_devices(document_id, nil))
    |> Enum.uniq_by(&{&1.share_id, &1.device_id, &1.principal_id})
    |> Enum.map(&encode_verification_device/1)
  end
end
