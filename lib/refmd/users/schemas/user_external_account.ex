defmodule RefMD.Users.UserExternalAccount do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_external_accounts" do
    belongs_to :user, RefMD.Users.User
    field :provider, :string
    field :provider_user_id, :string
    field :email, :string

    field :created_at, :utc_datetime_usec
  end

  def changeset(account, attrs) do
    account
    |> cast(attrs, [:user_id, :provider, :provider_user_id, :email])
    |> validate_required([:user_id, :provider, :provider_user_id])
    |> unique_constraint([:provider, :provider_user_id])
    |> unique_constraint([:user_id, :provider])
  end
end
