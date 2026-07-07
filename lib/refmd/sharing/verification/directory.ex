defmodule RefMD.Sharing.Verification.Directory do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Documents.DocumentSignerKey
  alias RefMD.Repo

  alias RefMD.Sharing.{
    Share,
    ShareParticipantDevice,
    ShareParticipantPrincipal
  }

  def verification_directory(share_id, document_id) do
    %{
      workspace_devices:
        (list_workspace_devices(document_id) ++ list_historical_workspace_devices(document_id))
        |> Enum.uniq_by(&verification_key_id/1),
      share_participant_devices:
        (list_share_participant_devices(share_id) ++
           (document_id
            |> list_historical_share_participant_devices(share_id)
            |> Enum.map(&encode_verification_device/1)))
        |> Enum.uniq_by(&verification_key_id/1)
    }
  end

  def document_share_participant_verification_directory(document_id) do
    %{
      workspace_devices: list_historical_workspace_devices(document_id),
      share_participant_devices:
        list_document_share_participant_devices(document_id)
        |> Enum.uniq_by(&verification_key_id/1)
    }
  end

  defp list_workspace_devices(document_id) do
    from(d in RefMD.Devices.Device,
      join: wm in RefMD.Workspaces.WorkspaceMember,
      on: wm.user_id == d.user_id,
      join: doc in RefMD.Documents.Document,
      on: doc.workspace_id == wm.workspace_id,
      left_join: ipk in RefMD.Encryption.UserIdentityPublicKey,
      on: ipk.user_id == d.user_id,
      where: doc.id == ^document_id and is_nil(d.revoked_at),
      select: %{
        device_id: d.id,
        user_id: d.user_id,
        hybrid_signing_public_key_material: d.hybrid_signing_public_key_material,
        signing_key_id: d.signing_key_id,
        hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
        encryption_key_id: d.encryption_key_id,
        approval_signature: d.approval_signature,
        approval_signature_surface: d.approval_signature_surface,
        approval_proof: d.approval_proof,
        approval_delivery_commitments: d.approval_delivery_commitments,
        approval_delivery_artifacts: d.approval_delivery_artifacts,
        client_nonce: d.client_nonce,
        identity_hybrid_encryption_public_key_material: ipk.hybrid_encryption_public_key_material,
        identity_hybrid_signing_public_key_material: ipk.hybrid_signing_public_key_material,
        historical: false
      }
    )
    |> Repo.all()
    |> Enum.map(&encode_verification_device/1)
  end

  defp list_historical_workspace_devices(document_id) do
    from(k in DocumentSignerKey,
      join: doc in RefMD.Documents.Document,
      on: doc.id == k.document_id,
      left_join: d in RefMD.Devices.Device,
      on: d.id == type(k.owner_id, Ecto.UUID),
      left_join: ipk in RefMD.Encryption.UserIdentityPublicKey,
      on: ipk.user_id == d.user_id,
      where:
        k.document_id == ^document_id and
          k.authority_kind == "workspace_device" and
          fragment("? = ?::text", k.authority_id, doc.workspace_id),
      select: %{
        device_id: type(k.owner_id, Ecto.UUID),
        user_id: d.user_id,
        hybrid_signing_public_key_material: k.hybrid_signing_public_key_material,
        signing_key_id: k.signing_key_id,
        hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
        encryption_key_id: d.encryption_key_id,
        approval_signature: d.approval_signature,
        approval_signature_surface: d.approval_signature_surface,
        approval_proof: d.approval_proof,
        approval_delivery_commitments: d.approval_delivery_commitments,
        approval_delivery_artifacts: d.approval_delivery_artifacts,
        client_nonce: d.client_nonce,
        identity_hybrid_encryption_public_key_material: ipk.hybrid_encryption_public_key_material,
        identity_hybrid_signing_public_key_material: ipk.hybrid_signing_public_key_material,
        historical: true
      }
    )
    |> Repo.all()
    |> Enum.map(&encode_verification_device/1)
  end

  defp list_share_participant_devices(share_id) do
    participant_devices =
      from(d in ShareParticipantDevice,
        join: p in ShareParticipantPrincipal,
        on: p.id == d.principal_id,
        join: s in Share,
        on: s.id == d.share_id,
        where: d.share_id == ^share_id and is_nil(d.revoked_at),
        select: %{
          share_id: d.share_id,
          share_token_hash: s.token_hash,
          share_permission: s.permission,
          share_password_protected: s.password_protected,
          authorization_public_key_material: s.authorization_public_key_material,
          device_id: d.id,
          principal_id: p.id,
          display_name: p.display_name,
          hybrid_signing_public_key_material: d.hybrid_signing_public_key_material,
          signing_key_id: d.signing_key_id,
          hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
          encryption_key_id: d.encryption_key_id,
          participant_device_kind: "share_participant_device",
          historical: false
        }
      )
      |> Repo.all()

    participant_devices
    |> Enum.uniq_by(&{&1.share_id, &1.device_id, &1.principal_id})
    |> Enum.map(&encode_verification_device/1)
  end

  defp encode_verification_device(device) do
    device
    |> encode_client_nonce()
    |> denormalize_approval_delivery_artifacts()
  end

  defp encode_client_nonce(%{client_nonce: client_nonce} = device) when is_binary(client_nonce) do
    Map.put(device, :client_nonce, Base.url_encode64(client_nonce, padding: false))
  end

  defp encode_client_nonce(device), do: device

  defp denormalize_approval_delivery_artifacts(%{approval_delivery_artifacts: artifacts} = device)
       when is_map(artifacts) do
    Map.put(
      device,
      :approval_delivery_artifacts,
      Map.update(
        artifacts,
        "device_approval_kek_initial_deliveries",
        [],
        &denormalize_device_approval_kek_initial_deliveries/1
      )
    )
  end

  defp denormalize_approval_delivery_artifacts(device), do: device

  defp denormalize_device_approval_kek_initial_deliveries(deliveries) when is_map(deliveries) do
    deliveries
    |> Enum.map(fn {workspace_id, delivery} ->
      %{"workspace_id" => workspace_id, "delivery" => delivery}
    end)
    |> Enum.sort_by(& &1["workspace_id"])
  end

  defp denormalize_device_approval_kek_initial_deliveries(deliveries), do: deliveries

  defp verification_key_id(%{signing_key_id: signing_key_id}) when is_binary(signing_key_id),
    do: signing_key_id

  defp list_direct_share_participant_devices(share_ids) do
    from(d in ShareParticipantDevice,
      join: p in ShareParticipantPrincipal,
      on: p.id == d.principal_id,
      join: s in Share,
      on: s.id == d.share_id,
      where: d.share_id in ^share_ids and is_nil(d.revoked_at),
      select: %{
        share_id: d.share_id,
        share_token_hash: s.token_hash,
        share_permission: s.permission,
        share_password_protected: s.password_protected,
        authorization_public_key_material: s.authorization_public_key_material,
        device_id: d.id,
        principal_id: p.id,
        display_name: p.display_name,
        hybrid_signing_public_key_material: d.hybrid_signing_public_key_material,
        signing_key_id: d.signing_key_id,
        hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
        encryption_key_id: d.encryption_key_id,
        participant_device_kind: "share_participant_device",
        historical: false
      }
    )
    |> Repo.all()
  end

  defp list_historical_share_participant_devices(document_id, _fallback_share_id) do
    list_historical_direct_share_participant_devices(document_id)
  end

  defp list_historical_direct_share_participant_devices(document_id) do
    from(k in DocumentSignerKey,
      left_join: d in ShareParticipantDevice,
      on: d.id == type(k.owner_id, Ecto.UUID),
      left_join: p in ShareParticipantPrincipal,
      on: p.id == d.principal_id,
      left_join: s in Share,
      on: s.id == d.share_id,
      where:
        k.document_id == ^document_id and
          k.authority_kind == "share_participant_device",
      select: %{
        share_id: k.authority_id,
        share_token_hash: s.token_hash,
        share_permission: s.permission,
        share_password_protected: s.password_protected,
        authorization_public_key_material: s.authorization_public_key_material,
        device_id: type(k.owner_id, Ecto.UUID),
        principal_id: fragment("split_part(?, ':', 2)", k.authority_context_key),
        display_name: p.display_name,
        hybrid_signing_public_key_material: k.hybrid_signing_public_key_material,
        signing_key_id: k.signing_key_id,
        hybrid_encryption_public_key_material: d.hybrid_encryption_public_key_material,
        encryption_key_id: d.encryption_key_id,
        participant_device_kind: "share_participant_device",
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
       list_historical_share_participant_devices(document_id, nil))
    |> Enum.uniq_by(&{&1.share_id, &1.device_id, &1.principal_id})
    |> Enum.map(&encode_verification_device/1)
  end
end
