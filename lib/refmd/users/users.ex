defmodule RefMD.Users do
  @moduledoc """
  The Users context. Manages user identity.
  """

  import Ecto.Query

  alias RefMD.Encryption.UserEncryptedMasterKey
  alias RefMD.Repo
  alias RefMD.Users.{User, UserExternalAccount, UserSettings, UserShortcut}

  def get_user(id), do: Repo.get(User, id)

  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: String.downcase(email))
  end

  def create_user(attrs) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  def create_user_with_struct(%User{} = user_struct, attrs) do
    user_struct
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  def create_user_settings(user_id) do
    %UserSettings{user_id: user_id, updated_at: DateTime.utc_now()}
    |> Repo.insert()
  end

  def get_user_settings(user_id) do
    Repo.get(UserSettings, user_id)
  end

  def update_user_settings(user_id, attrs) do
    case get_user_settings(user_id) do
      nil ->
        {:error, :not_found}

      settings ->
        settings
        |> UserSettings.changeset(attrs)
        |> Ecto.Changeset.force_change(:updated_at, DateTime.utc_now())
        |> Repo.update()
    end
  end

  def update_encryption_setup(user_id) do
    from(u in User, where: u.id == ^user_id)
    |> Repo.update_all(set: [encryption_setup_at: DateTime.utc_now()])
  end

  def get_user_external_accounts(user_id) do
    from(a in UserExternalAccount, where: a.user_id == ^user_id, order_by: [desc: :created_at])
    |> Repo.all()
  end

  def get_user_external_account(provider, provider_user_id)
      when is_binary(provider) and is_binary(provider_user_id) do
    Repo.get_by(UserExternalAccount, provider: provider, provider_user_id: provider_user_id)
  end

  def get_user_external_account_for_user(user_id, provider)
      when is_binary(user_id) and is_binary(provider) do
    Repo.get_by(UserExternalAccount, user_id: user_id, provider: provider)
  end

  def create_user_external_account(attrs) do
    %UserExternalAccount{created_at: DateTime.utc_now()}
    |> UserExternalAccount.changeset(attrs)
    |> Repo.insert()
  end

  def delete_user_external_account(user_id, account_id) do
    from(a in UserExternalAccount, where: a.id == ^account_id and a.user_id == ^user_id)
    |> Repo.delete_all()
  end

  def delete_user_external_account_by_provider(user_id, provider)
      when is_binary(user_id) and is_binary(provider) do
    from(a in UserExternalAccount, where: a.user_id == ^user_id and a.provider == ^provider)
    |> Repo.delete_all()
  end

  def unlink_external_account_preserving_login(user_id, provider)
      when is_binary(user_id) and is_binary(provider) do
    Repo.transaction(fn ->
      accounts =
        from(a in UserExternalAccount,
          where: a.user_id == ^user_id,
          order_by: [asc: :provider],
          lock: "FOR UPDATE"
        )
        |> Repo.all()

      master_key =
        from(k in UserEncryptedMasterKey,
          where: k.user_id == ^user_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      account = Enum.find(accounts, &(&1.provider == provider))

      cond do
        account == nil ->
          Repo.rollback(:external_account_not_found)

        last_external_auth_method?(accounts, provider, master_key) ->
          Repo.rollback(:last_auth_method_required)

        true ->
          Repo.delete!(account)
          :ok
      end
    end)
  end

  def unlink_external_account_preserving_login(_, _), do: {:error, :invalid_provider}

  defp last_external_auth_method?(accounts, provider, master_key) do
    not password_configured?(master_key) and
      not Enum.any?(accounts, &(&1.provider != provider))
  end

  defp password_configured?(%{auth_type: "password"}), do: true
  defp password_configured?(_master_key), do: false

  def get_user_shortcuts(user_id) do
    from(s in UserShortcut, where: s.user_id == ^user_id, order_by: [asc: :action])
    |> Repo.all()
  end

  def upsert_user_shortcut(attrs) do
    %UserShortcut{created_at: DateTime.utc_now()}
    |> UserShortcut.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:keys]},
      conflict_target: [:user_id, :action]
    )
  end

  def delete_user_shortcut(user_id, shortcut_id) do
    from(s in UserShortcut, where: s.id == ^shortcut_id and s.user_id == ^user_id)
    |> Repo.delete_all()
  end
end
