defmodule RefMD.Auth.PasswordResets do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.PasswordResetToken
  alias RefMD.Repo

  @password_reset_ttl 60 * 60
  @password_reset_rate_limit 5 * 60

  def create_password_reset_token(user_id) do
    token = :crypto.strong_rand_bytes(32)
    token_hash = Base.url_encode64(:crypto.hash(:sha256, token), padding: false)
    now = DateTime.utc_now()

    case %PasswordResetToken{created_at: now}
         |> PasswordResetToken.changeset(%{
           user_id: user_id,
           token_hash: token_hash,
           expires_at: DateTime.add(now, @password_reset_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _} -> {:ok, token}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def can_send_password_reset?(user_id) do
    cutoff = DateTime.add(DateTime.utc_now(), -@password_reset_rate_limit, :second)

    not Repo.exists?(
      from(t in PasswordResetToken,
        where: t.user_id == ^user_id and t.created_at > ^cutoff
      )
    )
  end

  def verify_password_reset_token(raw_token) do
    token_hash = Base.url_encode64(:crypto.hash(:sha256, raw_token), padding: false)
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      query =
        from(t in PasswordResetToken,
          where: t.token_hash == ^token_hash and t.expires_at > ^now,
          lock: "FOR UPDATE"
        )

      case Repo.one(query) do
        nil ->
          Repo.rollback(:invalid_token)

        token ->
          Repo.delete!(token)
          token.user_id
      end
    end)
  end

  def delete_expired_password_reset_tokens do
    now = DateTime.utc_now()

    from(t in PasswordResetToken, where: t.expires_at < ^now)
    |> Repo.delete_all()
  end
end
