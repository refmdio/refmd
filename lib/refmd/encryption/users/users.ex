defmodule RefMD.Encryption.Users do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Encoding
  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Devices.Device

  alias RefMD.Encryption.KeyDirectory

  alias RefMD.Encryption.{
    RotationPolicy,
    UserEncryptedIdentityKey,
    UserEncryptedMasterKey,
    UserIdentityPublicKey,
    UserIdentityRotationDeletionEvidence,
    WorkspaceMemberEnvelope
  }

  alias RefMD.Repo
  alias RefMD.Workspaces.{Workspace, WorkspaceGuestGrant, WorkspaceMember, WorkspaceRole}

  def create_identity_public_key(attrs) do
    attrs =
      attrs
      |> Map.put_new(:key_version, 1)
      |> Map.put_new(:lifecycle_state, "current")
      |> put_default_rotation_due_at()

    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.changeset(attrs)
    |> Repo.insert()
  end

  def create_guest_identity_public_key(attrs) do
    attrs =
      attrs
      |> Map.put_new(:key_version, 1)
      |> Map.put_new(:lifecycle_state, "current")
      |> put_default_rotation_due_at()

    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.guest_changeset(attrs)
    |> Repo.insert()
  end

  def create_encrypted_master_key(attrs) do
    %UserEncryptedMasterKey{}
    |> UserEncryptedMasterKey.changeset(attrs)
    |> Repo.insert()
  end

  def create_encrypted_identity_key(attrs) do
    changeset =
      %UserEncryptedIdentityKey{}
      |> UserEncryptedIdentityKey.changeset(attrs)
      |> validate_identity_public_key_refs()

    if changeset.valid? do
      Repo.insert(changeset)
    else
      {:error, changeset}
    end
  end

  def rotation_deletion_evidences_by_event_hash(event_hashes) when is_list(event_hashes) do
    from(e in UserIdentityRotationDeletionEvidence,
      where: e.old_key_deleted_event_hash in ^event_hashes
    )
    |> Repo.all()
    |> Map.new(&{&1.old_key_deleted_event_hash, &1})
  end

  def get_encrypted_master_key(user_id), do: Repo.get(UserEncryptedMasterKey, user_id)

  def update_master_key_kdf(user_id, attrs) do
    update_master_key(user_id, %{
      auth_key_hash: attrs.auth_key_hash,
      encrypted_umk: attrs.encrypted_umk,
      umk_nonce: attrs.umk_nonce,
      kdf_params: attrs.kdf_params
    })
  end

  def update_master_key_for_password_set(user_id, attrs) do
    update_master_key(user_id, %{
      auth_type: "password",
      kdf_type: "argon2id",
      auth_key_hash: attrs.auth_key_hash,
      salt: attrs.salt,
      encrypted_umk: attrs.encrypted_umk,
      umk_nonce: attrs.umk_nonce,
      kdf_params: attrs.kdf_params
    })
  end

  def update_recovery_key(user_id, attrs) do
    update_master_key(user_id, %{
      recovery_encrypted_umk: attrs.recovery_encrypted_umk,
      recovery_nonce: attrs.recovery_nonce,
      recovery_authorization_public_material: attrs.recovery_authorization_public_material,
      recovery_authorization_key_id: attrs.recovery_authorization_key_id
    })
  end

  def get_encrypted_identity_key(user_id) do
    Repo.get_by(UserEncryptedIdentityKey, user_id: user_id, is_current: true)
  end

  def get_pending_encrypted_identity_key(user_id) do
    from(k in UserEncryptedIdentityKey,
      join: p in UserIdentityPublicKey,
      on: p.user_id == k.user_id and p.key_version == k.identity_key_epoch,
      where: k.user_id == ^user_id and p.lifecycle_state == "pending" and k.is_current == false
    )
    |> Repo.one()
  end

  def get_encrypted_identity_key_by_version(user_id, key_version) do
    Repo.get_by(UserEncryptedIdentityKey, user_id: user_id, identity_key_epoch: key_version)
  end

  def get_identity_public_key(user_id, opts \\ []) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id and k.lifecycle_state == "current"
    )
    |> maybe_lock(Keyword.get(opts, :lock))
    |> Repo.one()
  end

  def get_pending_identity_public_key(user_id, opts \\ []) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id and k.lifecycle_state == "pending"
    )
    |> maybe_lock(Keyword.get(opts, :lock))
    |> Repo.one()
  end

  def identity_rotation_status(user_id) do
    current = get_identity_public_key(user_id)
    pending = get_pending_identity_public_key(user_id)
    required_targets = required_successor_envelope_targets(user_id)

    covered_targets =
      if pending do
        successor_envelope_targets(user_id, pending)
      else
        MapSet.new()
      end

    encrypted_current = get_encrypted_identity_key(user_id)

    Map.merge(identity_key_status_fields(current, pending), %{
      finalization_started:
        not is_nil(pending) and not is_nil(encrypted_current) and
          encrypted_current.identity_key_epoch == pending.key_version,
      required_workspace_count: MapSet.size(required_targets),
      required_workspace_targets:
        required_targets
        |> Enum.sort()
        |> Enum.map(fn {workspace_id, key_version} ->
          %{workspace_id: workspace_id, key_version: key_version}
        end),
      covered_workspace_count:
        MapSet.intersection(required_targets, covered_targets) |> MapSet.size(),
      envelopes_complete:
        not is_nil(pending) and MapSet.subset?(required_targets, covered_targets),
      workspace_rewraps:
        if(pending, do: expected_identity_workspace_rewraps(user_id, pending), else: [])
    })
  end

  defp identity_key_status_fields(current, pending) do
    %{
      current_key_version: field(current, :key_version),
      current_encryption_key_id: field(current, :encryption_key_id),
      current_signing_key_id: field(current, :signing_key_id),
      needs_rotation: field(current, :needs_rotation),
      rotation_due_at: field(current, :rotation_due_at),
      pending_key_version: field(pending, :key_version),
      pending_encryption_key_id: field(pending, :encryption_key_id),
      pending_signing_key_id: field(pending, :signing_key_id)
    }
  end

  defp field(nil, _field), do: nil
  defp field(record, field), do: Map.fetch!(record, field)

  defp maybe_lock(query, nil), do: query
  defp maybe_lock(query, "FOR SHARE"), do: from(row in query, lock: "FOR SHARE")

  def list_identity_public_keys(user_id) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id,
      order_by: [desc: k.key_version]
    )
    |> Repo.all()
  end

  def lock_identity_keys_for_membership(user_id) do
    keys =
      from(k in UserIdentityPublicKey,
        where: k.user_id == ^user_id,
        lock: "FOR SHARE"
      )
      |> Repo.all()

    case Enum.find(keys, &(&1.lifecycle_state == "current")) do
      nil when keys == [] ->
        :ok

      nil ->
        {:error, :identity_rotation_required}

      key ->
        if RotationPolicy.identity_overdue?(key),
          do: {:error, :identity_rotation_required},
          else: :ok
    end
  end

  def identity_key_for_new_encryption(user_id, opts \\ []) do
    case get_identity_public_key(user_id, opts) do
      nil ->
        {:error, :identity_key_missing}

      key ->
        if RotationPolicy.identity_overdue?(key),
          do: {:error, :identity_rotation_required},
          else: {:ok, key}
    end
  end

  def prepare_identity_rotation(user_id, attrs) when is_map(attrs) do
    Repo.transaction(fn ->
      lock_user!(user_id)
      current = lock_identity_key!(user_id, "current")

      if pending_identity_key_exists?(user_id) do
        Repo.rollback(:identity_rotation_already_pending)
      end

      next_version = current.key_version + 1
      public_attrs = Map.fetch!(attrs, :public_key)
      encrypted_attrs = Map.fetch!(attrs, :encrypted_key)

      pending_public =
        %UserIdentityPublicKey{}
        |> UserIdentityPublicKey.changeset(
          public_attrs
          |> Map.put(:user_id, user_id)
          |> Map.put(:key_version, next_version)
          |> Map.put(:lifecycle_state, "pending")
          |> Map.put(:rotation_due_at, RotationPolicy.next_identity_due_at())
          |> Map.put(:needs_rotation, false)
          |> Map.put(
            :pending_registration_challenge_hash,
            current.pending_registration_challenge_hash
          )
        )
        |> Repo.insert!()

      current
      |> Ecto.Changeset.change(
        needs_rotation: true,
        rotation_due_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
      )
      |> Repo.update!()

      %UserEncryptedIdentityKey{}
      |> UserEncryptedIdentityKey.changeset(
        encrypted_attrs
        |> Map.put(:user_id, user_id)
        |> Map.put(:identity_key_epoch, next_version)
        |> Map.put(:is_current, false)
        |> Map.put(:encryption_key_id, pending_public.encryption_key_id)
        |> Map.put(:signing_key_id, pending_public.signing_key_id)
      )
      |> validate_identity_public_key_refs(pending_public)
      |> Repo.insert!()

      RefMD.Encryption.append_user_key_directory!(
        user_id,
        Map.fetch!(attrs, :user_key_directory_events),
        Map.fetch!(attrs, :user_key_directory_checkpoint),
        checkpoint_signer_kind: "identity"
      )

      %{key_version: next_version, public_key: pending_public}
    end)
  rescue
    KeyError -> {:error, :invalid_identity_rotation}
    Ecto.InvalidChangesetError -> {:error, :invalid_identity_rotation}
    ArgumentError -> {:error, :invalid_identity_rotation}
  end

  def activate_identity_rotation(user_id, key_version) when is_integer(key_version) do
    Repo.transaction(fn ->
      lock_user!(user_id)
      current = lock_identity_key!(user_id, "current")
      pending = lock_identity_key!(user_id, "pending")
      ensure_identity_successor_activatable!(user_id, pending, key_version)
      encrypted_current = get_encrypted_identity_key(user_id)
      encrypted_pending = get_pending_encrypted_identity_key(user_id)

      unless encrypted_current && encrypted_current.identity_key_epoch == current.key_version &&
               encrypted_pending && encrypted_pending.identity_key_epoch == pending.key_version,
             do: Repo.rollback(:identity_rotation_incomplete)

      %{key_version: pending.key_version}
    end)
  end

  def activate_identity_rotation(_, _), do: {:error, :invalid_identity_rotation}

  defp ensure_identity_successor_activatable!(user_id, pending, key_version) do
    if pending.key_version != key_version or not successor_envelopes_complete?(user_id, pending) do
      Repo.rollback(:identity_rotation_incomplete)
    end
  end

  def finalize_identity_rotation(user_id, key_version, deletion_proof, key_directory)
      when is_integer(key_version) and is_map(deletion_proof) and is_map(key_directory) do
    assert_identity_device_deletion_proof_shapes!(deletion_proof)

    Repo.transaction(fn ->
      lock_user!(user_id)
      current = lock_identity_key!(user_id, "current")

      if current.key_version == key_version and is_nil(get_pending_identity_public_key(user_id)) do
        %{key_version: current.key_version, deleted_key_version: current.key_version - 1}
      else
        finalize_pending_identity_rotation!(
          user_id,
          key_version,
          deletion_proof,
          key_directory,
          current
        )
      end
    end)
  rescue
    KeyError -> {:error, :invalid_identity_rotation}
    ArgumentError -> {:error, :invalid_identity_rotation}
    Ecto.InvalidChangesetError -> {:error, :invalid_identity_rotation}
  end

  def finalize_identity_rotation(_, _, _, _), do: {:error, :invalid_identity_rotation}

  defp finalize_pending_identity_rotation!(
         user_id,
         key_version,
         deletion_proof,
         key_directory,
         current
       ) do
    pending = lock_identity_key!(user_id, "pending")

    if pending.key_version != key_version or not successor_envelopes_complete?(user_id, pending) or
         not valid_deletion_proof?(current, pending, deletion_proof) do
      Repo.rollback(:identity_rotation_incomplete)
    end

    validate_identity_rotation_lifecycle!(Map.fetch!(key_directory, :events), deletion_proof)
    validate_identity_device_deletion_proofs!(user_id, current, pending, deletion_proof)

    validate_identity_rotation_manifests!(
      user_id,
      current,
      pending,
      deletion_proof,
      key_directory
    )

    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    deletion_proof_hash = Hash.blake3_base64url(JCS.canonical_bytes!(deletion_proof))

    RefMD.Encryption.append_user_key_directory!(
      user_id,
      Map.fetch!(key_directory, :events),
      Map.fetch!(key_directory, :checkpoint),
      checkpoint_signer_kind: "identity"
    )

    unless valid_retirement_checkpoint?(
             current,
             pending,
             Map.fetch!(key_directory, :checkpoint)
           ),
           do: Repo.rollback(:identity_rotation_incomplete)

    old_key_deleted_event = key_directory.events |> List.last() |> Map.fetch!("payload")

    %UserIdentityRotationDeletionEvidence{}
    |> UserIdentityRotationDeletionEvidence.changeset(%{
      old_key_deleted_event_hash: KeyDirectory.event_hash(old_key_deleted_event),
      user_id: user_id,
      rotation_kind: "identity",
      scope_kind: "user",
      scope_id: user_id,
      old_key_version: current.key_version,
      deletion_manifest: Map.fetch!(deletion_proof, "deletion_manifest"),
      device_key_deletion_proofs: %{
        "proofs" => Map.fetch!(deletion_proof, "device_key_deletion_proofs")
      },
      wipe_required_device_ids: Map.fetch!(deletion_proof, "wipe_required_device_ids")
    })
    |> Repo.insert!()

    current
    |> Ecto.Changeset.change(
      lifecycle_state: "historical",
      needs_rotation: false,
      superseded_at: now,
      private_key_deletion_proof_hash: deletion_proof_hash
    )
    |> Repo.update!()

    pending
    |> Ecto.Changeset.change(lifecycle_state: "current")
    |> Repo.update!()

    mark_identity_wipe_required_devices!(
      user_id,
      deletion_proof["wipe_required_device_ids"],
      now
    )

    from(k in UserEncryptedIdentityKey,
      where: k.user_id == ^user_id and k.identity_key_epoch == ^current.key_version
    )
    |> Repo.update_all(set: [is_current: false, updated_at: now])

    from(k in UserEncryptedIdentityKey,
      where: k.user_id == ^user_id and k.identity_key_epoch == ^pending.key_version
    )
    |> Repo.update_all(set: [is_current: true, updated_at: now])

    %{key_version: pending.key_version, deleted_key_version: current.key_version}
  end

  defp validate_identity_public_key_refs(changeset) do
    case Ecto.Changeset.get_field(changeset, :user_id) do
      user_id when is_binary(user_id) ->
        now = DateTime.utc_now()

        from(k in UserIdentityPublicKey,
          where:
            k.user_id == ^user_id and k.lifecycle_state == "current" and
              k.needs_rotation == false and k.rotation_due_at > ^now
        )
        |> Repo.one()
        |> validate_identity_public_key_refs(changeset)

      _ ->
        changeset
    end
  end

  defp validate_identity_public_key_refs(nil, changeset) do
    changeset
    |> Ecto.Changeset.add_error(:encryption_key_id, "must match identity public key")
    |> Ecto.Changeset.add_error(:signing_key_id, "must match identity public key")
  end

  defp validate_identity_public_key_refs(%UserIdentityPublicKey{} = public_key, changeset) do
    changeset
    |> validate_identity_public_key_ref(:encryption_key_id, public_key.encryption_key_id)
    |> validate_identity_public_key_ref(:signing_key_id, public_key.signing_key_id)
  end

  defp validate_identity_public_key_refs(changeset, %UserIdentityPublicKey{} = public_key) do
    validate_identity_public_key_refs(public_key, changeset)
  end

  defp put_default_rotation_due_at(attrs) do
    if Map.has_key?(attrs, :rotation_due_at) or Map.has_key?(attrs, "rotation_due_at") do
      attrs
    else
      Map.put(attrs, :rotation_due_at, RotationPolicy.next_identity_due_at())
    end
  end

  defp lock_identity_key!(user_id, lifecycle_state) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id and k.lifecycle_state == ^lifecycle_state,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
    |> case do
      %UserIdentityPublicKey{} = key -> key
      nil -> Repo.rollback(:identity_key_missing)
    end
  end

  defp pending_identity_key_exists?(user_id) do
    from(k in UserIdentityPublicKey,
      where: k.user_id == ^user_id and k.lifecycle_state == "pending"
    )
    |> Repo.exists?()
  end

  defp successor_envelopes_complete?(user_id, pending) do
    required_targets = required_successor_envelope_targets(user_id)
    covered_targets = successor_envelope_targets(user_id, pending)
    MapSet.subset?(required_targets, covered_targets)
  end

  defp required_successor_envelope_targets(user_id) do
    member_targets =
      from(wm in WorkspaceMember,
        join: w in Workspace,
        on: w.id == wm.workspace_id,
        join: r in WorkspaceRole,
        on: r.id == wm.role_id,
        where: wm.user_id == ^user_id and r.base_role != "guest",
        select: {w.id, w.current_kek_version}
      )
      |> Repo.all()
      |> MapSet.new()

    guest_targets =
      from(g in WorkspaceGuestGrant,
        join: w in Workspace,
        on: w.id == g.workspace_id,
        where: g.user_id == ^user_id and g.scope_kind == "workspace" and is_nil(g.revoked_at),
        select: {w.id, w.current_kek_version}
      )
      |> Repo.all()
      |> MapSet.new()

    MapSet.union(member_targets, guest_targets)
  end

  defp successor_envelope_targets(user_id, pending) do
    expected_recipient_key_id = Encoding.decode_base64url!(pending.encryption_key_id, 32)

    from(e in WorkspaceMemberEnvelope,
      where: e.target_user_id == ^user_id and e.recipient_key_id == ^expected_recipient_key_id,
      select: {e.workspace_id, e.key_version}
    )
    |> Repo.all()
    |> MapSet.new()
  end

  defp valid_deletion_proof?(current, pending, proof) do
    Map.take(proof, [
      "old_encryption_key_id",
      "old_private_key_use_blocked",
      "old_signing_key_id",
      "old_version",
      "persistent_identity_deletion_authorized",
      "successor_encryption_key_id",
      "successor_signing_key_id",
      "successor_version"
    ]) == %{
      "old_encryption_key_id" => current.encryption_key_id,
      "old_private_key_use_blocked" => true,
      "old_signing_key_id" => current.signing_key_id,
      "old_version" => current.key_version,
      "persistent_identity_deletion_authorized" => true,
      "successor_encryption_key_id" => pending.encryption_key_id,
      "successor_signing_key_id" => pending.signing_key_id,
      "successor_version" => pending.key_version
    }
  end

  defp validate_identity_rotation_lifecycle!(events, proof) do
    types = Enum.map(events, &get_in(&1, ["payload", "event_type"]))

    unless types == [
             "signing_key_revoked",
             "encryption_key_revoked",
             "rotation_completed",
             "old_key_deleted"
           ],
           do: raise(ArgumentError, "identity_rotation_lifecycle_invalid")

    completed_payload = events |> Enum.at(2) |> Map.fetch!("payload")
    deleted_body = events |> Enum.at(3) |> get_in(["payload", "body"])

    true =
      KeyDirectory.event_hash(completed_payload) ==
        proof["rotation_completed_event_hash"]

    true = deleted_body["deletion_manifest_hash"] == proof["deletion_manifest_hash"]
  end

  defp validate_identity_rotation_manifests!(user_id, current, pending, proof, key_directory) do
    completion = Map.fetch!(proof, "completion_manifest")
    deletion = Map.fetch!(proof, "deletion_manifest")
    checkpoint = KeyDirectory.current_checkpoint("user", user_id)
    events = Map.fetch!(key_directory, :events)
    [signing_revoked, _encryption_revoked, completed, deleted] = events

    computed_completion_hash = Hash.blake3_base64url(JCS.canonical_bytes!(completion))

    unless computed_completion_hash == proof["completion_manifest_hash"] do
      raise ArgumentError, "identity completion manifest hash mismatch"
    end

    unless Hash.blake3_base64url(JCS.canonical_bytes!(deletion)) ==
             proof["deletion_manifest_hash"] do
      raise ArgumentError, "identity deletion manifest hash mismatch"
    end

    true =
      completed["payload"]["body"]["completion_manifest_hash"] ==
        proof["completion_manifest_hash"]

    true = deleted["payload"]["body"]["deletion_manifest_hash"] == proof["deletion_manifest_hash"]

    started_sequence = checkpoint.covered_event_head_sequence - 1

    [started] =
      KeyDirectory.events_after_until("user", user_id, started_sequence - 1, started_sequence)

    workspace_rewraps = expected_identity_workspace_rewraps(user_id, pending)
    workspace_rewraps_hash = canonical_hash(%{"workspace_rewraps" => workspace_rewraps})
    old_checkpoint_hash = checkpoint.previous_checkpoint_hash
    new_checkpoint_hash = checkpoint.checkpoint_hash

    true =
      Map.take(completion, [
        "protocol",
        "version",
        "rotation_kind",
        "scope_kind",
        "scope_id",
        "old_identity_signing_key_id",
        "old_identity_encryption_key_id",
        "new_identity_signing_key_id",
        "new_identity_encryption_key_id",
        "started_event_hash",
        "old_user_checkpoint_hash",
        "new_user_checkpoint_hash",
        "new_user_checkpoint_sequence",
        "old_identity_checkpoint_signature_hash",
        "new_identity_checkpoint_signature_hash",
        "workspace_rewraps",
        "workspace_rewraps_hash",
        "revoked_old_identity_public_key_event_hash",
        "semantic_state_proof_hash"
      ]) == %{
        "protocol" => "refmd.identity-rotation-completion-manifest",
        "version" => 1,
        "rotation_kind" => "identity",
        "scope_kind" => "user",
        "scope_id" => user_id,
        "old_identity_signing_key_id" => current.signing_key_id,
        "old_identity_encryption_key_id" => current.encryption_key_id,
        "new_identity_signing_key_id" => pending.signing_key_id,
        "new_identity_encryption_key_id" => pending.encryption_key_id,
        "started_event_hash" => started.event_hash,
        "old_user_checkpoint_hash" => old_checkpoint_hash,
        "new_user_checkpoint_hash" => new_checkpoint_hash,
        "new_user_checkpoint_sequence" => checkpoint.sequence,
        "old_identity_checkpoint_signature_hash" =>
          checkpoint_signature_hash(checkpoint.signatures, current.signing_key_id),
        "new_identity_checkpoint_signature_hash" =>
          checkpoint_signature_hash(checkpoint.signatures, pending.signing_key_id),
        "workspace_rewraps" => workspace_rewraps,
        "workspace_rewraps_hash" => workspace_rewraps_hash,
        "revoked_old_identity_public_key_event_hash" =>
          KeyDirectory.event_hash(signing_revoked["payload"]),
        "semantic_state_proof_hash" =>
          canonical_hash(%{
            "old_user_checkpoint_hash" => old_checkpoint_hash,
            "new_user_checkpoint_hash" => new_checkpoint_hash,
            "workspace_rewraps_hash" => workspace_rewraps_hash
          })
      }

    proof_hashes =
      proof["device_key_deletion_proofs"]
      |> Enum.map(&canonical_hash(Map.fetch!(&1, "payload")))
      |> Enum.sort()

    deleted_identity_hash =
      canonical_hash(%{
        "key_ids" => Enum.sort([current.encryption_key_id, current.signing_key_id])
      })

    true =
      deletion == %{
        "protocol" => "refmd.identity-old-key-deletion-manifest",
        "version" => 1,
        "rotation_kind" => "identity",
        "scope_kind" => "user",
        "scope_id" => user_id,
        "old_identity_signing_key_id" => current.signing_key_id,
        "old_identity_encryption_key_id" => current.encryption_key_id,
        "new_identity_signing_key_id" => pending.signing_key_id,
        "rotation_completed_event_hash" => proof["rotation_completed_event_hash"],
        "deleted_identity_secret_ids_hash" => deleted_identity_hash,
        "active_identity_deletion_proofs_hash" =>
          canonical_hash(%{"proof_hashes" => proof_hashes}),
        "wipe_required_device_ids_hash" =>
          canonical_hash(%{"device_ids" => Enum.sort(proof["wipe_required_device_ids"])}),
        "server_rejects_old_identity_after_sequence" => deleted["payload"]["sequence"]
      }
  end

  defp expected_identity_workspace_rewraps(user_id, pending) do
    from(e in WorkspaceMemberEnvelope,
      where:
        e.target_user_id == ^user_id and
          e.recipient_key_id == ^Encoding.decode_base64url!(pending.encryption_key_id, 32),
      order_by: [asc: e.workspace_id],
      select: e
    )
    |> Repo.all()
    |> Enum.map(fn envelope ->
      envelope_id = %{
        "workspace_id" => envelope.workspace_id,
        "target_user_id" => envelope.target_user_id,
        "key_version" => envelope.key_version
      }

      %{
        "workspace_id" => envelope.workspace_id,
        "workspace_checkpoint_hash" =>
          Encoding.encode_base64url(envelope.operation_checkpoint_hash),
        "member_envelope_manifest_hash" =>
          canonical_hash(%{
            "member_envelopes" => [
              Map.put(
                envelope_id,
                "wrap_event_body_hash",
                Encoding.encode_base64url(envelope.wrap_event_body_hash)
              )
            ]
          }),
        "affected_member_envelope_ids_hash" =>
          canonical_hash(%{"member_envelope_ids" => [envelope_id]}),
        "new_identity_recipient_key_id" => Encoding.encode_base64url(envelope.recipient_key_id)
      }
    end)
  end

  defp checkpoint_signature_hash(signatures, signing_key_id) do
    signatures
    |> Enum.find(fn signature -> signature["signer"]["signing_key_id"] == signing_key_id end)
    |> canonical_hash()
  end

  defp canonical_hash(value), do: Hash.blake3_base64url(JCS.canonical_bytes!(value))

  defp assert_identity_device_deletion_proof_shapes!(proof) do
    case Map.fetch(proof, "device_key_deletion_proofs") do
      {:ok, proofs} when is_list(proofs) ->
        unless Enum.all?(proofs, &canonical_identity_device_deletion_proof?/1),
          do: raise(ArgumentError, "identity_device_deletion_proof_invalid")

      {:ok, _} ->
        raise ArgumentError, "identity_device_deletion_proofs_invalid"

      :error ->
        :ok
    end
  end

  defp canonical_identity_device_deletion_proof?(signed) when is_map(signed),
    do: Enum.sort(Map.keys(signed)) == ["payload", "signature", "transcript"]

  defp canonical_identity_device_deletion_proof?(_), do: false

  defp validate_identity_device_deletion_proofs!(user_id, current, pending, proof) do
    active_devices =
      from(d in Device,
        where:
          d.user_id == ^user_id and is_nil(d.revoked_at) and
            is_nil(d.identity_wipe_required_at),
        select: d,
        lock: "FOR UPDATE"
      )
      |> Repo.all()
      |> Map.new(&{&1.id, &1})

    proofs = Map.fetch!(proof, "device_key_deletion_proofs")
    wipe_ids = Map.fetch!(proof, "wipe_required_device_ids") |> MapSet.new()
    completed_hash = Map.fetch!(proof, "rotation_completed_event_hash")
    Hash.assert_blake3_base64url!(completed_hash)

    checkpoint = KeyDirectory.current_checkpoint("user", user_id)
    true = not is_nil(checkpoint)
    old_checkpoint_hash = checkpoint.previous_checkpoint_hash
    true = is_binary(old_checkpoint_hash)
    new_checkpoint_hash = checkpoint.checkpoint_hash

    deleted_identity_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "key_ids" => Enum.sort([current.encryption_key_id, current.signing_key_id])
        })
      )

    proof_ids =
      Enum.map(proofs, fn signed ->
        payload = Map.fetch!(signed, "payload")
        transcript = Map.fetch!(signed, "transcript")
        signature = Map.fetch!(signed, "signature")
        device = Map.fetch!(active_devices, payload["device_id"])

        true = payload["protocol"] == "refmd.identity-key-deletion-proof"
        true = payload["user_id"] == user_id
        true = payload["scope_kind"] == "user" and payload["scope_id"] == user_id
        true = payload["rotation_kind"] == "identity"
        true = payload["old_identity_signing_key_id"] == current.signing_key_id
        true = payload["old_identity_encryption_key_id"] == current.encryption_key_id
        true = payload["new_identity_signing_key_id"] == pending.signing_key_id
        true = payload["new_identity_encryption_key_id"] == pending.encryption_key_id
        true = payload["old_user_checkpoint_hash"] == old_checkpoint_hash
        true = payload["new_user_checkpoint_hash"] == new_checkpoint_hash
        true = payload["rotation_completed_event_hash"] == completed_hash
        true = payload["deleted_identity_secret_ids_hash"] == deleted_identity_hash

        :ok =
          Signature.verify_hybrid_signature_result(
            "device_key_deletion_proof",
            transcript,
            signature,
            device.hybrid_signing_public_key_material,
            %{
              signer: %{id: device.id, signing_key_id: device.signing_key_id, revoked_at: nil},
              deletion: %{
                scope_id: user_id,
                rotation_completed_event_hash: completed_hash,
                old_identity_signing_key_id: current.signing_key_id,
                old_identity_encryption_key_id: current.encryption_key_id,
                new_identity_signing_key_id: pending.signing_key_id,
                new_identity_encryption_key_id: pending.encryption_key_id,
                old_user_checkpoint_hash: old_checkpoint_hash,
                new_user_checkpoint_hash: new_checkpoint_hash,
                deleted_identity_secret_ids_hash: deleted_identity_hash,
                checkpoint_sequence: checkpoint.sequence,
                checkpoint_hash: new_checkpoint_hash
              }
            }
          )

        device.id
      end)
      |> MapSet.new()

    active_ids = active_devices |> Map.keys() |> MapSet.new()

    unless MapSet.disjoint?(proof_ids, wipe_ids) and
             MapSet.equal?(MapSet.union(proof_ids, wipe_ids), active_ids),
           do: raise(ArgumentError, "identity_deletion_proof_coverage_incomplete")
  end

  defp mark_identity_wipe_required_devices!(user_id, device_ids, now) do
    from(d in Device, where: d.id in ^device_ids)
    |> Repo.update_all(set: [identity_wipe_required_at: now])

    Enum.each(device_ids, fn device_id ->
      Phoenix.PubSub.broadcast(
        RefMD.PubSub,
        "device_revocation:#{user_id}",
        {:device_revoked, device_id}
      )
    end)
  end

  defp lock_user!(user_id) do
    from(u in RefMD.Users.User, where: u.id == ^user_id, lock: "FOR UPDATE")
    |> Repo.one!()
  end

  defp valid_retirement_checkpoint?(current, pending, %{"payload" => payload}) do
    entries = payload["identity_keys"] || []

    key_entry_revoked?(entries, current.signing_key_id) and
      key_entry_revoked?(entries, current.encryption_key_id) and
      key_entry_active?(entries, pending.signing_key_id) and
      key_entry_active?(entries, pending.encryption_key_id)
  end

  defp valid_retirement_checkpoint?(_, _, _), do: false

  defp key_entry_revoked?(entries, key_id) do
    Enum.any?(entries, &(&1["key_id"] == key_id and Map.has_key?(&1, "revoked_at")))
  end

  defp key_entry_active?(entries, key_id) do
    Enum.any?(entries, &(&1["key_id"] == key_id and not Map.has_key?(&1, "revoked_at")))
  end

  defp validate_identity_public_key_ref(changeset, field, expected_key_id) do
    if Ecto.Changeset.get_field(changeset, field) == expected_key_id do
      changeset
    else
      Ecto.Changeset.add_error(changeset, field, "must match identity public key")
    end
  end

  defp update_master_key(user_id, attrs) do
    case Repo.get(UserEncryptedMasterKey, user_id) do
      nil ->
        {:error, :not_found}

      master_key ->
        master_key
        |> UserEncryptedMasterKey.changeset(attrs)
        |> Repo.update()
    end
  end
end
