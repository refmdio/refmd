defmodule RefMD.Users do
  @moduledoc """
  The Users context. Manages user identity.
  """

  import Ecto.Query

  alias RefMD.Repo
  alias RefMD.Users.{User, UserExternalAccount, UserSettings, UserShortcut}

  @spec get_user(Ecto.UUID.t()) :: User.t() | nil
  def get_user(id), do: Repo.get(User, id)

  @spec get_user_by_email(String.t()) :: User.t() | nil
  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: String.downcase(email))
  end

  @spec create_user(map()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def create_user(attrs) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_user_with_struct(User.t(), map()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def create_user_with_struct(%User{} = user_struct, attrs) do
    user_struct
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_user_settings(Ecto.UUID.t()) ::
          {:ok, UserSettings.t()} | {:error, Ecto.Changeset.t()}
  def create_user_settings(user_id) do
    %UserSettings{user_id: user_id, updated_at: DateTime.utc_now()}
    |> Repo.insert()
  end

  @spec get_user_settings(Ecto.UUID.t()) :: UserSettings.t() | nil
  def get_user_settings(user_id) do
    Repo.get(UserSettings, user_id)
  end

  @spec update_user_settings(Ecto.UUID.t(), map()) ::
          {:ok, UserSettings.t()} | {:error, Ecto.Changeset.t() | :not_found}
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

  @spec update_encryption_setup(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def update_encryption_setup(user_id) do
    from(u in User, where: u.id == ^user_id)
    |> Repo.update_all(set: [encryption_setup_at: DateTime.utc_now()])
  end

  # ── External Accounts ──────────────────────────

  @spec get_user_external_accounts(Ecto.UUID.t()) :: [UserExternalAccount.t()]
  def get_user_external_accounts(user_id) do
    from(a in UserExternalAccount, where: a.user_id == ^user_id, order_by: [desc: :created_at])
    |> Repo.all()
  end

  @spec create_user_external_account(map()) ::
          {:ok, UserExternalAccount.t()} | {:error, Ecto.Changeset.t()}
  def create_user_external_account(attrs) do
    %UserExternalAccount{created_at: DateTime.utc_now()}
    |> UserExternalAccount.changeset(attrs)
    |> Repo.insert()
  end

  @spec delete_user_external_account(Ecto.UUID.t(), Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_user_external_account(user_id, account_id) do
    from(a in UserExternalAccount, where: a.id == ^account_id and a.user_id == ^user_id)
    |> Repo.delete_all()
  end

  # ── Shortcuts ──────────────────────────────────

  @spec get_user_shortcuts(Ecto.UUID.t()) :: [UserShortcut.t()]
  def get_user_shortcuts(user_id) do
    from(s in UserShortcut, where: s.user_id == ^user_id, order_by: [asc: :action])
    |> Repo.all()
  end

  @spec upsert_user_shortcut(map()) :: {:ok, UserShortcut.t()} | {:error, Ecto.Changeset.t()}
  def upsert_user_shortcut(attrs) do
    %UserShortcut{created_at: DateTime.utc_now()}
    |> UserShortcut.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:keys]},
      conflict_target: [:user_id, :action]
    )
  end

  @spec delete_user_shortcut(Ecto.UUID.t(), Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_user_shortcut(user_id, shortcut_id) do
    from(s in UserShortcut, where: s.id == ^shortcut_id and s.user_id == ^user_id)
    |> Repo.delete_all()
  end
end
