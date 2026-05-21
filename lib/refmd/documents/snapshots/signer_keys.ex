defmodule RefMD.Documents.Snapshots.SignerKeys do
  @moduledoc false

  alias RefMD.Crypto.Signature
  alias RefMD.Repo
  alias RefMD.Sharing

  @spec record_document_signer!(Ecto.UUID.t(), Ecto.UUID.t(), map()) :: any()
  def record_document_signer!(
        document_id,
        _actor_id,
        %{session_kind: :share_participant} = attrs
      ) do
    principal_id = Map.fetch!(attrs, :principal_id)
    share_id = Map.fetch!(attrs, :share_id)

    case Sharing.share_participant_signer(share_id, principal_id, attrs.owner_id) do
      {:ok, signer} ->
        upsert_document_signer!(%{
          document_id: document_id,
          authority_kind: "share_participant_device",
          authority_id: share_id,
          authority_context_key: share_authority_context_key(share_id, principal_id),
          authority_scope_id: share_id,
          authority_permission_version: attrs.authority_permission_version,
          key_checkpoint_sequence: attrs.key_checkpoint_sequence,
          key_checkpoint_hash: attrs.key_checkpoint_hash,
          owner_kind: attrs.owner_kind,
          owner_id: attrs.owner_id,
          principal_id: principal_id,
          user_id: nil,
          hybrid_signing_public_key_material: signer.hybrid_signing_public_key_material
        })

      _ ->
        Repo.rollback(:device_revoked)
    end
  end

  def record_document_signer!(document_id, actor_id, attrs) do
    record_member_document_signer!(
      document_id,
      actor_id,
      attrs.owner_id,
      %{
        authority_kind: "workspace_device",
        authority_id: attrs.authority_id,
        authority_context_key: attrs.authority_context_key,
        authority_scope_id: attrs.authority_scope_id,
        authority_permission_version: attrs.authority_permission_version,
        key_checkpoint_sequence: attrs.key_checkpoint_sequence,
        key_checkpoint_hash: attrs.key_checkpoint_hash,
        owner_kind: attrs.owner_kind,
        owner_id: attrs.owner_id,
        principal_id: nil,
        user_id: actor_id
      }
    )
  end

  defp record_member_document_signer!(document_id, user_id, device_id, authority_attrs) do
    signer =
      Repo.query!(
        """
        SELECT
          d.id,
          d.hybrid_signing_public_key_material
        FROM devices d
        WHERE d.id = $1 AND d.user_id = $2
        """,
        [Ecto.UUID.dump!(device_id), Ecto.UUID.dump!(user_id)]
      )

    case signer.rows do
      [
        [
          _selected_device_id,
          hybrid_signing_public_key_material
        ]
      ] ->
        upsert_document_signer!(%{
          document_id: document_id,
          authority_kind: authority_attrs.authority_kind,
          authority_id: authority_attrs.authority_id,
          authority_context_key: authority_attrs.authority_context_key,
          authority_scope_id: authority_attrs.authority_scope_id,
          authority_permission_version: authority_attrs.authority_permission_version,
          key_checkpoint_sequence: authority_attrs.key_checkpoint_sequence,
          key_checkpoint_hash: authority_attrs.key_checkpoint_hash,
          owner_kind: authority_attrs.owner_kind,
          owner_id: authority_attrs.owner_id,
          principal_id: authority_attrs.principal_id,
          user_id: authority_attrs.user_id,
          hybrid_signing_public_key_material: hybrid_signing_public_key_material
        })

      _ ->
        Repo.rollback(:device_revoked)
    end
  end

  defp upsert_document_signer!(attrs) do
    attrs = assert_document_signer_attrs!(attrs)

    Repo.query!(
      """
      INSERT INTO document_signer_keys (
        document_id, authority_kind, authority_id, authority_context_key, authority_scope_id,
        authority_permission_version, key_checkpoint_sequence, key_checkpoint_hash,
        owner_kind, owner_id, hybrid_signing_public_key_material, signing_key_id,
        first_seen_at, last_seen_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
      ON CONFLICT (
        document_id, signing_key_id, authority_context_key, key_checkpoint_hash
      )
      DO UPDATE SET
        last_seen_at = NOW()
      """,
      [
        Ecto.UUID.dump!(attrs.document_id),
        attrs.authority_kind,
        attrs.authority_id,
        attrs.authority_context_key,
        attrs.authority_scope_id,
        attrs.authority_permission_version,
        attrs.key_checkpoint_sequence,
        attrs.key_checkpoint_hash,
        attrs.owner_kind,
        attrs.owner_id,
        attrs.hybrid_signing_public_key_material,
        attrs.signing_key_id
      ]
    )
  end

  defp assert_document_signer_attrs!(attrs) do
    material = Map.fetch!(attrs, :hybrid_signing_public_key_material)
    Signature.assert_public_key_material!(material)
    assert_signer_owner!(attrs, material)
    assert_authority_shape!(attrs)
    Map.put(attrs, :signing_key_id, Signature.compute_signing_key_id!(material))
  end

  defp assert_signer_owner!(attrs, material) do
    assert_equal!(material["owner_kind"], attrs.owner_kind, "document_owner_kind_mismatch")
    assert_equal!(material["owner_id"], attrs.owner_id, "document_owner_id_mismatch")
    :ok
  end

  defp assert_authority_shape!(%{
         authority_kind: "workspace_device",
         owner_kind: "device",
         principal_id: nil,
         user_id: user_id
       })
       when is_binary(user_id),
       do: :ok

  defp assert_authority_shape!(%{
         authority_kind: "share_participant_device",
         authority_id: share_id,
         authority_context_key: context_key,
         authority_scope_id: share_id,
         owner_kind: "share_participant_device",
         principal_id: principal_id,
         user_id: nil
       })
       when is_binary(share_id) and is_binary(principal_id) do
    assert_equal!(
      context_key,
      share_authority_context_key(share_id, principal_id),
      "document_signer_authority_context_mismatch"
    )
  end

  defp assert_authority_shape!(_), do: raise(ArgumentError, "document_signer_authority_invalid")

  defp assert_equal!(value, value, _reason), do: :ok
  defp assert_equal!(_, _, reason), do: raise(ArgumentError, reason)

  defp share_authority_context_key(share_id, principal_id), do: "#{share_id}:#{principal_id}"
end
