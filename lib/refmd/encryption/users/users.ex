defmodule RefMD.Encryption.Users do
  @moduledoc false

  alias RefMD.Encryption.{
    UserEncryptedIdentityKey,
    UserEncryptedMasterKey,
    UserIdentityPublicKey
  }

  alias RefMD.Repo

  def create_identity_public_key(attrs) do
    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.changeset(attrs)
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

  def get_encrypted_identity_key(user_id), do: Repo.get(UserEncryptedIdentityKey, user_id)

  def get_identity_public_key(user_id), do: Repo.get(UserIdentityPublicKey, user_id)

  defp validate_identity_public_key_refs(changeset) do
    case Ecto.Changeset.get_field(changeset, :user_id) do
      user_id when is_binary(user_id) ->
        UserIdentityPublicKey
        |> Repo.get(user_id)
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
