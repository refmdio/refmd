defmodule RefMD.Encryption do
  @moduledoc """
  The Encryption context. Manages E2EE key storage and distribution.
  """

  import Ecto.Query

  alias RefMD.Encryption.{
    DocumentEncryptedKey,
    UserEncryptedIdentityKey,
    UserEncryptedMasterKey,
    UserIdentityPublicKey,
    WorkspaceEncryptedKey,
    WorkspaceKekBackup,
    WorkspaceMemberEnvelope
  }

  alias RefMD.Repo

  # ── User Keys ──────────────────────────────────

  @spec create_user_identity_public_key(map()) ::
          {:ok, UserIdentityPublicKey.t()} | {:error, Ecto.Changeset.t()}
  def create_user_identity_public_key(attrs) do
    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_user_encrypted_master_key(map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, Ecto.Changeset.t()}
  def create_user_encrypted_master_key(attrs) do
    %UserEncryptedMasterKey{}
    |> UserEncryptedMasterKey.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_user_encrypted_identity_key(map()) ::
          {:ok, UserEncryptedIdentityKey.t()} | {:error, Ecto.Changeset.t()}
  def create_user_encrypted_identity_key(attrs) do
    %UserEncryptedIdentityKey{}
    |> UserEncryptedIdentityKey.changeset(attrs)
    |> Repo.insert()
  end

  @spec get_user_encrypted_master_key(Ecto.UUID.t()) :: UserEncryptedMasterKey.t() | nil
  def get_user_encrypted_master_key(user_id) do
    Repo.get(UserEncryptedMasterKey, user_id)
  end

  @spec update_master_key_kdf(Ecto.UUID.t(), map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_master_key_kdf(user_id, attrs) do
    case Repo.get(UserEncryptedMasterKey, user_id) do
      nil ->
        {:error, :not_found}

      master_key ->
        master_key
        |> Ecto.Changeset.change(%{
          auth_key_hash: attrs.auth_key_hash,
          encrypted_umk: attrs.encrypted_umk,
          umk_nonce: attrs.umk_nonce,
          kdf_params: attrs.kdf_params
        })
        |> Repo.update()
    end
  end

  @spec update_master_key_for_password_set(Ecto.UUID.t(), map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_master_key_for_password_set(user_id, attrs) do
    case Repo.get(UserEncryptedMasterKey, user_id) do
      nil ->
        {:error, :not_found}

      master_key ->
        master_key
        |> Ecto.Changeset.change(%{
          auth_type: "password",
          kdf_type: "argon2id",
          auth_key_hash: attrs.auth_key_hash,
          salt: attrs.salt,
          encrypted_umk: attrs.encrypted_umk,
          umk_nonce: attrs.umk_nonce,
          kdf_params: attrs.kdf_params
        })
        |> Repo.update()
    end
  end

  @spec update_recovery_key(Ecto.UUID.t(), map()) ::
          {:ok, UserEncryptedMasterKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_recovery_key(user_id, attrs) do
    case Repo.get(UserEncryptedMasterKey, user_id) do
      nil ->
        {:error, :not_found}

      master_key ->
        master_key
        |> Ecto.Changeset.change(%{
          recovery_encrypted_umk: attrs.recovery_encrypted_umk,
          recovery_nonce: attrs.recovery_nonce
        })
        |> Repo.update()
    end
  end

  @spec get_user_encrypted_identity_key(Ecto.UUID.t()) :: UserEncryptedIdentityKey.t() | nil
  def get_user_encrypted_identity_key(user_id) do
    Repo.get(UserEncryptedIdentityKey, user_id)
  end

  @spec get_user_identity_public_key(Ecto.UUID.t()) :: UserIdentityPublicKey.t() | nil
  def get_user_identity_public_key(user_id) do
    Repo.get(UserIdentityPublicKey, user_id)
  end

  @spec get_workspace_member_identity_keys(Ecto.UUID.t()) :: [
          %{user_id: Ecto.UUID.t(), ecdh_public_key: binary()}
        ]
  def get_workspace_member_identity_keys(workspace_id) do
    from(wm in RefMD.Workspaces.WorkspaceMember,
      join: ipk in UserIdentityPublicKey,
      on: ipk.user_id == wm.user_id,
      where: wm.workspace_id == ^workspace_id,
      select: %{user_id: wm.user_id, ecdh_public_key: ipk.ecdh_public_key}
    )
    |> Repo.all()
  end

  # ── Workspace Keys ─────────────────────────────

  @spec create_workspace_encrypted_key(map()) ::
          {:ok, WorkspaceEncryptedKey.t()} | {:error, :invalid_sender_device | Ecto.Changeset.t()}
  def create_workspace_encrypted_key(attrs) do
    user_id = attrs[:user_id] || attrs["user_id"]
    sender_device_id = attrs[:sender_device_id] || attrs["sender_device_id"]

    if sender_device_id != nil and
         not RefMD.Devices.user_owns_active_device?(user_id, sender_device_id) do
      {:error, :invalid_sender_device}
    else
      %WorkspaceEncryptedKey{created_at: DateTime.utc_now()}
      |> WorkspaceEncryptedKey.changeset(attrs)
      |> Repo.insert()
    end
  end

  @spec delete_workspace_encrypted_key(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), integer()) ::
          {non_neg_integer(), nil | [term()]}
  def delete_workspace_encrypted_key(workspace_id, user_id, device_id, key_version) do
    from(k in WorkspaceEncryptedKey,
      where:
        k.workspace_id == ^workspace_id and
          k.user_id == ^user_id and
          k.device_id == ^device_id and
          k.key_version == ^key_version
    )
    |> Repo.delete_all()
  end

  @spec get_workspace_encrypted_keys(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          [WorkspaceEncryptedKey.t()]
  def get_workspace_encrypted_keys(workspace_id, user_id, device_id) do
    from(k in WorkspaceEncryptedKey,
      where:
        k.workspace_id == ^workspace_id and
          k.user_id == ^user_id and
          k.device_id == ^device_id and
          k.is_active == true
    )
    |> Repo.all()
  end

  @spec user_has_active_kek?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def user_has_active_kek?(workspace_id, user_id) do
    from(k in WorkspaceEncryptedKey,
      where:
        k.workspace_id == ^workspace_id and
          k.user_id == ^user_id and
          k.is_active == true,
      select: count()
    )
    |> Repo.one()
    |> Kernel.>(0)
  end

  # ── KEK Backups ───────────────────────────────

  @spec create_workspace_kek_backup(map()) ::
          {:ok, WorkspaceKekBackup.t()} | {:error, Ecto.Changeset.t()}
  def create_workspace_kek_backup(attrs) do
    Repo.transaction(fn ->
      # Deactivate existing active backup for this (workspace, user) to satisfy partial unique index
      from(b in WorkspaceKekBackup,
        where:
          b.workspace_id == ^attrs.workspace_id and
            b.user_id == ^attrs.user_id and
            b.is_active == true
      )
      |> Repo.update_all(set: [is_active: false])

      case %WorkspaceKekBackup{created_at: DateTime.utc_now()}
           |> WorkspaceKekBackup.changeset(attrs)
           |> Repo.insert() do
        {:ok, backup} -> backup
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @spec get_active_kek_backup(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceKekBackup.t() | nil
  def get_active_kek_backup(workspace_id, user_id) do
    from(b in WorkspaceKekBackup,
      where:
        b.workspace_id == ^workspace_id and
          b.user_id == ^user_id and
          b.is_active == true
    )
    |> Repo.one()
  end

  @spec get_max_active_kek_version(Ecto.UUID.t()) :: integer() | nil
  def get_max_active_kek_version(workspace_id) do
    from(k in WorkspaceEncryptedKey,
      where: k.workspace_id == ^workspace_id and k.is_active == true,
      select: max(k.key_version)
    )
    |> Repo.one()
  end

  # ── Member Envelopes ─────────────────────────

  @spec save_member_envelopes(Ecto.UUID.t(), [map()]) :: {:ok, any()} | {:error, any()}
  def save_member_envelopes(workspace_id, envelopes) do
    now = DateTime.utc_now()

    parsed =
      Enum.reduce_while(envelopes, {:ok, []}, fn env, {:ok, acc} ->
        with {:ok, encrypted_kek} <- safe_decode64(env["encrypted_kek"]),
             {:ok, nonce} <- safe_decode64(env["nonce"]) do
          changeset =
            %WorkspaceMemberEnvelope{created_at: now}
            |> WorkspaceMemberEnvelope.changeset(%{
              workspace_id: workspace_id,
              target_user_id: env["target_user_id"],
              key_version: env["key_version"],
              sender_device_id: env["sender_device_id"],
              encrypted_kek: encrypted_kek,
              nonce: nonce
            })

          {:cont, {:ok, [changeset | acc]}}
        else
          :error -> {:halt, {:error, :invalid_base64}}
        end
      end)

    case parsed do
      {:error, reason} ->
        {:error, reason}

      {:ok, changesets} ->
        Repo.transaction(fn ->
          Enum.each(changesets, &insert_envelope_or_rollback/1)
        end)
    end
  end

  defp insert_envelope_or_rollback(changeset) do
    case Repo.insert(changeset,
           on_conflict: {:replace, [:encrypted_kek, :nonce, :sender_device_id, :created_at]},
           conflict_target: [:workspace_id, :target_user_id, :key_version]
         ) do
      {:ok, _} -> :ok
      {:error, changeset} -> Repo.rollback({:invalid_envelope, changeset})
    end
  end

  defp safe_decode64(base64) when is_binary(base64) do
    Base.url_decode64(base64, padding: false)
  end

  defp safe_decode64(_), do: :error

  @spec get_member_envelope(Ecto.UUID.t(), Ecto.UUID.t()) :: WorkspaceMemberEnvelope.t() | nil
  def get_member_envelope(workspace_id, user_id) do
    from(e in WorkspaceMemberEnvelope,
      where: e.workspace_id == ^workspace_id and e.target_user_id == ^user_id,
      order_by: [desc: :key_version],
      limit: 1
    )
    |> Repo.one()
  end

  @spec all_user_devices_have_key?(Ecto.UUID.t(), Ecto.UUID.t(), integer()) :: boolean()
  def all_user_devices_have_key?(workspace_id, user_id, key_version) do
    active_device_ids =
      from(d in RefMD.Devices.Device,
        where: d.user_id == ^user_id and is_nil(d.revoked_at),
        select: d.id
      )
      |> Repo.all()
      |> MapSet.new()

    covered_device_ids =
      from(k in WorkspaceEncryptedKey,
        where:
          k.workspace_id == ^workspace_id and
            k.user_id == ^user_id and
            k.key_version == ^key_version and
            k.is_active == true,
        select: k.device_id
      )
      |> Repo.all()
      |> MapSet.new()

    MapSet.subset?(active_device_ids, covered_device_ids)
  end

  @spec all_members_have_envelope?(Ecto.UUID.t(), integer()) :: boolean()
  def all_members_have_envelope?(workspace_id, key_version) do
    member_count =
      from(wm in RefMD.Workspaces.WorkspaceMember,
        where: wm.workspace_id == ^workspace_id,
        select: count()
      )
      |> Repo.one()

    envelope_count =
      from(e in WorkspaceMemberEnvelope,
        where: e.workspace_id == ^workspace_id and e.key_version == ^key_version,
        select: count()
      )
      |> Repo.one()

    envelope_count >= member_count
  end

  # ── Document Keys ──────────────────────────────

  @spec create_document_encrypted_key(map()) ::
          {:ok, DocumentEncryptedKey.t()} | {:error, Ecto.Changeset.t()}
  def create_document_encrypted_key(attrs) do
    %DocumentEncryptedKey{created_at: DateTime.utc_now()}
    |> DocumentEncryptedKey.changeset(attrs)
    |> Repo.insert()
  end

  @spec get_active_document_encrypted_key(Ecto.UUID.t()) :: DocumentEncryptedKey.t() | nil
  def get_active_document_encrypted_key(document_id) do
    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id and k.is_active == true
    )
    |> Repo.one()
  end

  # ── Login Keys Response ────────────────────────

  @spec get_login_keys(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: map()
  def get_login_keys(user_id, device_id) do
    %{
      encrypted_master_key: get_user_encrypted_master_key(user_id),
      encrypted_identity_key: get_user_encrypted_identity_key(user_id),
      identity_public_key: get_user_identity_public_key(user_id),
      device_encrypted_umk:
        if(device_id, do: RefMD.Devices.get_device_encrypted_umk(user_id, device_id))
    }
  end
end
