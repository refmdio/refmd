defmodule RefMD.Encryption do
  @moduledoc """
  The Encryption context. Manages E2EE key storage and distribution.
  """

  import Ecto.Query
  alias RefMD.Repo

  alias RefMD.Encryption.{
    UserIdentityPublicKey,
    UserEncryptedMasterKey,
    UserEncryptedIdentityKey,
    DeviceEncryptedUMK,
    WorkspaceEncryptedKey,
    WorkspaceKekBackup,
    DocumentEncryptedKey
  }

  # ── User Keys ──────────────────────────────────

  def create_user_identity_public_key(attrs) do
    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.changeset(attrs)
    |> Repo.insert()
  end

  def create_user_encrypted_master_key(attrs) do
    %UserEncryptedMasterKey{}
    |> UserEncryptedMasterKey.changeset(attrs)
    |> Repo.insert()
  end

  def create_user_encrypted_identity_key(attrs) do
    %UserEncryptedIdentityKey{}
    |> UserEncryptedIdentityKey.changeset(attrs)
    |> Repo.insert()
  end

  def get_user_encrypted_master_key(user_id) do
    Repo.get(UserEncryptedMasterKey, user_id)
  end

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

  def get_user_encrypted_identity_key(user_id) do
    Repo.get(UserEncryptedIdentityKey, user_id)
  end

  def get_user_identity_public_key(user_id) do
    Repo.get(UserIdentityPublicKey, user_id)
  end

  # ── Device Keys ────────────────────────────────

  def create_device_encrypted_umk(attrs) do
    %DeviceEncryptedUMK{created_at: DateTime.utc_now()}
    |> DeviceEncryptedUMK.changeset(attrs)
    |> Repo.insert()
  end

  def get_device_encrypted_umk(user_id, device_id) do
    from(d in DeviceEncryptedUMK,
      where: d.user_id == ^user_id and d.device_id == ^device_id
    )
    |> Repo.one()
  end

  # ── Workspace Keys ─────────────────────────────

  def create_workspace_encrypted_key(attrs) do
    user_id = attrs[:user_id] || attrs["user_id"]
    sender_device_id = attrs[:sender_device_id] || attrs["sender_device_id"]

    if sender_device_id != nil and
         not RefMD.Accounts.user_owns_active_device?(user_id, sender_device_id) do
      {:error, :invalid_sender_device}
    else
      %WorkspaceEncryptedKey{created_at: DateTime.utc_now()}
      |> WorkspaceEncryptedKey.changeset(attrs)
      |> Repo.insert()
    end
  end

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

  # ── KEK Backups ───────────────────────────────

  def create_workspace_kek_backup(attrs) do
    %WorkspaceKekBackup{created_at: DateTime.utc_now()}
    |> WorkspaceKekBackup.changeset(attrs)
    |> Repo.insert()
  end

  def get_active_kek_backup(workspace_id, user_id) do
    from(b in WorkspaceKekBackup,
      where:
        b.workspace_id == ^workspace_id and
          b.user_id == ^user_id and
          b.is_active == true
    )
    |> Repo.one()
  end

  def get_max_active_kek_version(workspace_id) do
    from(k in WorkspaceEncryptedKey,
      where: k.workspace_id == ^workspace_id and k.is_active == true,
      select: max(k.key_version)
    )
    |> Repo.one()
  end

  # ── Document Keys ──────────────────────────────

  def create_document_encrypted_key(attrs) do
    %DocumentEncryptedKey{created_at: DateTime.utc_now()}
    |> DocumentEncryptedKey.changeset(attrs)
    |> Repo.insert()
  end

  def get_active_document_encrypted_key(document_id) do
    from(k in DocumentEncryptedKey,
      where: k.document_id == ^document_id and k.is_active == true
    )
    |> Repo.one()
  end

  # ── Login Keys Response ────────────────────────

  def get_login_keys(user_id, device_id) do
    %{
      encrypted_master_key: get_user_encrypted_master_key(user_id),
      encrypted_identity_key: get_user_encrypted_identity_key(user_id),
      identity_public_key: get_user_identity_public_key(user_id),
      device_encrypted_umk: get_device_encrypted_umk(user_id, device_id)
    }
  end
end
