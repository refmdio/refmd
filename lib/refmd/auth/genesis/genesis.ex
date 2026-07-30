defmodule RefMD.Auth.Genesis do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.{PendingAccountGenesis, PendingGenesisChallenge, PendingGenesisSession}
  alias RefMD.Crypto.Hash
  alias RefMD.Repo
  alias RefMD.Users.User

  @pending_ttl_seconds 15 * 60
  @role_names ~w(owner admin editor viewer)
  @registration_protocol "refmd.password-account-registration"
  @registration_version 1
  @challenge_ttl_seconds 5 * 60
  @password_kdf_params %{
    "memory_kib" => 65_536,
    "iterations" => 3,
    "parallelism" => 4
  }

  def begin_password_registration(attrs) when is_map(attrs) do
    with :ok <- assert_literal(Map.get(attrs, "protocol"), @registration_protocol),
         :ok <- assert_literal(Map.get(attrs, "version"), @registration_version),
         {:ok, reserved_user_id} <- uuid_v4(Map.get(attrs, "reserved_user_id")),
         {:ok, email} <- normalize_email(Map.get(attrs, "email")),
         {:ok, display_name} <- normalize_display_name(Map.get(attrs, "display_name")),
         {:ok, auth_key} <- decode_base64url(Map.get(attrs, "auth_key_b64u"), 32),
         {:ok, salt} <- decode_base64url(Map.get(attrs, "salt_b64u"), 16),
         :ok <- assert_literal(Map.get(attrs, "kdf_type"), "argon2id"),
         :ok <- assert_literal(Map.get(attrs, "kdf_params"), @password_kdf_params) do
      now = DateTime.utc_now()
      expires_at = DateTime.add(now, @pending_ttl_seconds, :second)
      token = :crypto.strong_rand_bytes(32)

      Repo.transaction(fn ->
        lock_identifier!("account-genesis:email:#{email}")
        lock_identifier!("account-genesis:user:#{reserved_user_id}")
        assert_email_available!(email, now)
        assert_user_id_available!(reserved_user_id, now)

        registration_id = Ecto.UUID.generate()

        genesis =
          %PendingAccountGenesis{}
          |> PendingAccountGenesis.changeset(%{
            registration_id: registration_id,
            reserved_user_id: reserved_user_id,
            reserved_workspace_id: Ecto.UUID.generate(),
            reserved_workspace_role_ids: Map.new(@role_names, &{&1, Ecto.UUID.generate()}),
            normalized_email: email,
            display_name: display_name,
            credential: %{
              "kind" => "password",
              "auth_key_verifier" =>
                Bcrypt.hash_pwd_salt(Base.url_encode64(auth_key, padding: false)),
              "salt_b64u" => Base.url_encode64(salt, padding: false),
              "kdf_type" => "argon2id",
              "kdf_params" => @password_kdf_params
            },
            expires_at: expires_at,
            created_at: now
          })
          |> Repo.insert!()

        %PendingGenesisSession{}
        |> PendingGenesisSession.changeset(%{
          registration_id: registration_id,
          token_hash: Hash.blake3_base64url(token),
          expires_at: expires_at,
          created_at: now
        })
        |> Repo.insert!()

        %{genesis: genesis, token: token}
      end)
    end
  rescue
    error in Ecto.ConstraintError -> {:error, constraint_reason(error)}
    error in Ecto.InvalidChangesetError -> {:error, error.changeset}
  end

  def begin_password_registration(_), do: {:error, :invalid_registration}

  def get_pending_by_token(token) when is_binary(token) do
    now = DateTime.utc_now()
    token_hash = Hash.blake3_base64url(token)

    from(s in PendingGenesisSession,
      join: g in PendingAccountGenesis,
      on: g.registration_id == s.registration_id,
      where:
        s.token_hash == ^token_hash and is_nil(s.consumed_at) and s.expires_at > ^now and
          is_nil(g.consumed_at) and g.expires_at > ^now,
      select: {g, s}
    )
    |> Repo.one()
    |> case do
      {%PendingAccountGenesis{} = genesis, %PendingGenesisSession{} = session} ->
        {:ok, genesis, session}

      nil ->
        {:error, :invalid_genesis_session}
    end
  end

  def get_pending_by_token(_), do: {:error, :invalid_genesis_session}

  def issue_challenge(%PendingAccountGenesis{} = genesis, %PendingGenesisSession{} = session) do
    now = DateTime.utc_now()

    expires_at =
      Enum.min_by(
        [
          genesis.expires_at,
          session.expires_at,
          DateTime.add(now, @challenge_ttl_seconds, :second)
        ],
        &DateTime.to_unix(&1, :microsecond)
      )

    challenge = :crypto.strong_rand_bytes(32)

    Repo.transaction(fn ->
      locked_session =
        from(s in PendingGenesisSession,
          where: s.registration_id == ^genesis.registration_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one!()

      if locked_session.token_hash != session.token_hash or not is_nil(locked_session.consumed_at) or
           DateTime.compare(locked_session.expires_at, now) != :gt do
        Repo.rollback(:invalid_genesis_session)
      end

      Repo.delete_all(
        from(c in PendingGenesisChallenge, where: c.registration_id == ^genesis.registration_id)
      )

      %PendingGenesisChallenge{}
      |> PendingGenesisChallenge.changeset(%{
        registration_id: genesis.registration_id,
        pending_genesis_session_token_hash: session.token_hash,
        challenge_hash: Hash.blake3_base64url(challenge),
        expires_at: expires_at,
        created_at: now
      })
      |> Repo.insert!()

      %{challenge: challenge, expires_at: expires_at}
    end)
  end

  def decode_cookie(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, token} when byte_size(token) == 32 -> {:ok, token}
      _ -> {:error, :invalid_genesis_session}
    end
  end

  def decode_cookie(_), do: {:error, :invalid_genesis_session}

  defp assert_email_available!(email, now) do
    if Repo.exists?(from(u in User, where: u.email == ^email)) or
         Repo.exists?(
           from(g in PendingAccountGenesis,
             where: g.normalized_email == ^email and is_nil(g.consumed_at) and g.expires_at > ^now
           )
         ) do
      Repo.rollback(:email_taken)
    end
  end

  defp assert_user_id_available!(user_id, now) do
    if Repo.exists?(from(u in User, where: u.id == ^user_id)) or
         Repo.exists?(
           from(g in PendingAccountGenesis,
             where:
               g.reserved_user_id == ^user_id and is_nil(g.consumed_at) and g.expires_at > ^now
           )
         ) do
      Repo.rollback(:account_genesis_conflict)
    end
  end

  defp lock_identifier!(identifier) do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [identifier])
  end

  defp normalize_email(value) when is_binary(value) do
    normalized = String.downcase(value)

    with true <- byte_size(normalized) <= 254,
         [local, domain] <- String.split(normalized, "@"),
         true <- byte_size(local) in 1..64,
         true <- byte_size(domain) in 1..253,
         true <- Regex.match?(~r/^[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~-]+$/, local),
         false <- String.starts_with?(local, "."),
         false <- String.ends_with?(local, "."),
         false <- String.contains?(local, ".."),
         labels when labels != [] <- String.split(domain, "."),
         true <- Enum.all?(labels, &valid_email_domain_label?/1) do
      {:ok, normalized}
    else
      _ -> {:error, :invalid_email}
    end
  end

  defp normalize_email(_), do: {:error, :invalid_email}

  defp normalize_display_name(value) when is_binary(value) do
    normalized = value |> String.normalize(:nfkc) |> String.trim()

    if String.length(normalized) in 1..80 and not Regex.match?(~r/\p{C}/u, normalized),
      do: {:ok, normalized},
      else: {:error, :invalid_display_name}
  end

  defp normalize_display_name(_), do: {:error, :invalid_display_name}

  defp decode_base64url(value, expected_size) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, decoded} when byte_size(decoded) == expected_size -> {:ok, decoded}
      _ -> {:error, :invalid_registration}
    end
  end

  defp decode_base64url(_, _), do: {:error, :invalid_registration}

  defp assert_literal(value, value), do: :ok
  defp assert_literal(_, _), do: {:error, :invalid_registration}

  defp uuid_v4(value) when is_binary(value) do
    if Regex.match?(
         ~r/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
         value
       ),
       do: {:ok, value},
       else: {:error, :invalid_registration}
  end

  defp uuid_v4(_), do: {:error, :invalid_registration}

  defp valid_email_domain_label?(label) do
    byte_size(label) in 1..63 and
      Regex.match?(~r/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/, label)
  end

  defp constraint_reason(%{constraint: constraint})
       when constraint in [
              "pending_account_geneses_normalized_email_index",
              "pending_account_geneses_reserved_user_id_index",
              "pending_account_geneses_reserved_workspace_id_index"
            ],
       do: :account_genesis_conflict

  defp constraint_reason(_), do: :invalid_registration
end
