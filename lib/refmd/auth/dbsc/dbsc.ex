defmodule RefMD.Auth.DBSC do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.DBSCSessionBinding
  alias RefMD.Auth.Session
  alias RefMD.Crypto.TokenSigning
  alias RefMD.Repo
  alias RefMD.Sharing.ShareParticipantSession

  @registration_salt "dbsc_registration_v1"
  @registration_ttl_seconds 5 * 60
  @credential_ttl_seconds 10 * 60
  @challenge_grace_seconds 60

  @session_kinds ["user", "share_participant", "mount"]

  def registration_header(session_kind, session_id, path)
      when session_kind in @session_kinds and is_binary(session_id) and is_binary(path) do
    challenge = random_base64url(32)

    authorization =
      TokenSigning.sign(@registration_salt, %{
        "session_kind" => session_kind,
        "session_id" => session_id,
        "challenge" => challenge
      })

    {:ok,
     "(ES256);path=\"#{sf_string(path)}\";challenge=\"#{challenge}\";authorization=\"#{sf_string(authorization)}\""}
  end

  def registration_header(_, _, _), do: {:error, :invalid_dbsc_session}

  def register_session(
        session_kind,
        session,
        secure_session_response,
        token_issuer \\ &random_bound_token/1
      )

  def register_session(
        session_kind,
        session,
        secure_session_response,
        token_issuer
      )
      when session_kind in @session_kinds and is_map(session) do
    with {:ok, proof} <- parse_proof(secure_session_response),
         {:ok, authorization} <- required_claim(proof.payload, "authorization"),
         {:ok, authorization_payload} <- verify_registration_authorization(authorization),
         :ok <- require_registration_session(authorization_payload, session_kind, session.id),
         {:ok, challenge} <- required_claim(proof.payload, "jti"),
         true <- challenge == authorization_payload["challenge"],
         :ok <- verify_registration_proof(proof) do
      upsert_binding(session_kind, session, proof.header["jwk"], token_issuer)
    else
      _ -> {:error, :invalid_dbsc_proof}
    end
  end

  def register_session(_, _, _, _), do: {:error, :invalid_dbsc_session}

  def refresh_session(session_kind, session, session_identifier, secure_session_response)
      when session_kind in @session_kinds and is_map(session) and is_binary(session_identifier) do
    now = DateTime.utc_now()

    with %DBSCSessionBinding{} = binding <-
           get_active_binding_by_identifier(session_kind, session.id, session_identifier, now),
         {:ok, proof} <- parse_proof(secure_session_response),
         :ok <- verify_refresh_proof(proof, binding),
         {:ok, challenge} <- required_claim(proof.payload, "jti"),
         true <- valid_refresh_challenge?(binding, challenge, now) do
      issue_bound_cookie(binding, now, &random_bound_token/1)
    else
      _ -> {:error, :invalid_dbsc_proof}
    end
  end

  def refresh_session(_, _, _, _), do: {:error, :invalid_dbsc_session}

  def refresh_session_by_identifier(session_kind, session_identifier, secure_session_response) do
    refresh_session_by_identifier(
      session_kind,
      session_identifier,
      secure_session_response,
      &random_bound_token/1
    )
  end

  def refresh_session_by_identifier(
        session_kind,
        session_identifier,
        secure_session_response,
        token_issuer
      )
      when session_kind in @session_kinds and is_binary(session_identifier) do
    now = DateTime.utc_now()

    with %DBSCSessionBinding{} = binding <-
           get_active_binding_by_identifier(session_kind, session_identifier, now),
         {:ok, proof} <- parse_proof(secure_session_response),
         :ok <- verify_refresh_proof(proof, binding),
         {:ok, challenge} <- required_claim(proof.payload, "jti"),
         true <- valid_refresh_challenge?(binding, challenge, now) do
      issue_bound_cookie(binding, now, token_issuer)
    else
      _ -> {:error, :invalid_dbsc_proof}
    end
  end

  def refresh_session_by_identifier(_, _, _, _), do: {:error, :invalid_dbsc_session}

  def bound_cookie_status(session_kind, session_id, dbsc_cookie)
      when session_kind in @session_kinds and is_binary(session_id) do
    now = DateTime.utc_now()

    case get_active_binding(session_kind, session_id, now) do
      nil ->
        :not_registered

      %DBSCSessionBinding{} = binding ->
        if valid_bound_cookie?(binding, dbsc_cookie, now) do
          {:ok, binding}
        else
          {:error, binding}
        end
    end
  end

  def bound_cookie_status(_, _, _), do: :not_registered

  def delete_binding(session_kind, session_id)
      when session_kind in @session_kinds and is_binary(session_id) do
    from(b in DBSCSessionBinding,
      where: b.session_kind == ^session_kind and b.session_id == ^session_id
    )
    |> Repo.delete_all()
  end

  def delete_binding(_, _), do: {0, nil}

  def session_instructions(%DBSCSessionBinding{} = binding, origin, credential_name)
      when is_binary(origin) and is_binary(credential_name) do
    %{
      session_identifier: binding.session_identifier,
      refresh_url: refresh_path(binding.session_kind),
      scope: %{
        origin: origin,
        include_site: false,
        scope_specification: [
          %{type: "exclude", domain: "*", path: "/api/auth/dbsc"}
        ]
      },
      credentials: [
        %{
          type: "cookie",
          name: credential_name,
          attributes: "Path=/; Secure; HttpOnly; SameSite=Lax"
        }
      ],
      allowed_refresh_initiators: []
    }
  end

  def challenge_header(%DBSCSessionBinding{} = binding),
    do:
      "\"#{sf_string(binding.current_challenge)}\";id=\"#{sf_string(binding.session_identifier)}\""

  def registration_path("user"), do: "/api/auth/dbsc/register"
  def registration_path("share_participant"), do: "/api/auth/dbsc/share/register"
  def registration_path("mount"), do: "/api/auth/dbsc/mount/register"

  def refresh_path("user"), do: "/api/auth/dbsc/refresh"
  def refresh_path("share_participant"), do: "/api/auth/dbsc/share/refresh"
  def refresh_path("mount"), do: "/api/auth/dbsc/mount/refresh"

  def credential_ttl_seconds, do: @credential_ttl_seconds

  defp verify_registration_authorization(authorization) do
    TokenSigning.verify(@registration_salt, authorization, max_age: @registration_ttl_seconds)
  end

  defp require_registration_session(payload, session_kind, session_id) do
    if payload["session_kind"] == session_kind and payload["session_id"] == session_id and
         is_binary(payload["challenge"]) do
      :ok
    else
      {:error, :invalid_registration_authorization}
    end
  end

  defp upsert_binding(session_kind, session, jwk, token_issuer) do
    now = DateTime.utc_now()

    attrs = %{
      session_kind: session_kind,
      session_id: session.id,
      session_identifier: random_base64url(32),
      public_key_jwk: public_jwk!(jwk),
      current_challenge: random_base64url(32),
      previous_challenge: nil,
      previous_challenge_expires_at: nil,
      binding_expires_at: session.expires_at,
      created_at: now,
      updated_at: now
    }

    Repo.transaction(fn ->
      from(b in DBSCSessionBinding,
        where: b.session_kind == ^session_kind and b.session_id == ^session.id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()
      |> case do
        nil ->
          %DBSCSessionBinding{}
          |> DBSCSessionBinding.changeset(attrs)
          |> Repo.insert!()

        %DBSCSessionBinding{} = binding ->
          binding
          |> DBSCSessionBinding.changeset(Map.delete(attrs, :created_at))
          |> Repo.update!()
      end
      |> issue_bound_cookie(now, token_issuer)
      |> case do
        {:ok, binding, token} -> {binding, token}
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, {binding, token}} -> {:ok, binding, token}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_dbsc_proof}
  end

  defp issue_bound_cookie(%DBSCSessionBinding{} = binding, now, token_issuer) do
    previous_challenge = binding.current_challenge

    with {:ok, token} <- token_issuer.(binding),
         token_hash = token_hash(token),
         attrs = %{
           current_token_hash: token_hash,
           previous_challenge: previous_challenge,
           previous_challenge_expires_at: DateTime.add(now, @challenge_grace_seconds, :second),
           current_challenge: random_base64url(32),
           credential_expires_at: DateTime.add(now, @credential_ttl_seconds, :second),
           last_verified_at: now,
           updated_at: now
         },
         :ok <- persist_bound_cookie_token(binding, token_hash, now),
         {:ok, updated} <- binding |> DBSCSessionBinding.changeset(attrs) |> Repo.update() do
      {:ok, updated, token}
    else
      {:error, %Ecto.Changeset{}} -> {:error, :invalid_dbsc_binding}
      {:error, reason} -> {:error, reason}
    end
  end

  defp persist_bound_cookie_token(
         %DBSCSessionBinding{session_kind: "user", session_id: session_id},
         token_hash,
         now
       ) do
    from(s in Session, where: s.id == ^session_id and s.expires_at > ^now)
    |> Repo.update_all(set: [token_hash: token_hash, last_seen_at: now])
    |> case do
      {1, _} -> :ok
      _ -> {:error, :invalid_dbsc_session}
    end
  end

  defp persist_bound_cookie_token(
         %DBSCSessionBinding{session_kind: "share_participant", session_id: session_id},
         token_hash,
         now
       ) do
    from(s in ShareParticipantSession, where: s.id == ^session_id and s.expires_at > ^now)
    |> Repo.update_all(set: [token_hash: token_hash, last_seen_at: now])
    |> case do
      {1, _} -> :ok
      _ -> {:error, :invalid_dbsc_session}
    end
  end

  defp persist_bound_cookie_token(%DBSCSessionBinding{session_kind: "mount"}, _token_hash, _now),
    do: :ok

  defp persist_bound_cookie_token(_binding, _token_hash, _now),
    do: {:error, :invalid_dbsc_session}

  defp random_bound_token(_binding), do: {:ok, :crypto.strong_rand_bytes(32)}

  defp get_active_binding(session_kind, session_id, now) do
    from(b in DBSCSessionBinding,
      where:
        b.session_kind == ^session_kind and b.session_id == ^session_id and
          b.binding_expires_at > ^now
    )
    |> Repo.one()
  end

  defp get_active_binding_by_identifier(session_kind, session_id, session_identifier, now) do
    from(b in DBSCSessionBinding,
      where:
        b.session_kind == ^session_kind and b.session_id == ^session_id and
          b.session_identifier == ^session_identifier and b.binding_expires_at > ^now,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp get_active_binding_by_identifier(session_kind, session_identifier, now) do
    from(b in DBSCSessionBinding,
      where:
        b.session_kind == ^session_kind and b.session_identifier == ^session_identifier and
          b.binding_expires_at > ^now,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp valid_bound_cookie?(
         %DBSCSessionBinding{
           current_token_hash: expected,
           credential_expires_at: credential_expires_at
         },
         token_base64,
         now
       )
       when is_binary(expected) and is_binary(token_base64) do
    with true <- credential_expires_at && DateTime.compare(credential_expires_at, now) == :gt,
         {:ok, token} <- Base.url_decode64(token_base64, padding: false) do
      Plug.Crypto.secure_compare(expected, token_hash(token))
    else
      _ -> false
    end
  end

  defp valid_bound_cookie?(_, _, _), do: false

  defp valid_refresh_challenge?(%DBSCSessionBinding{} = binding, challenge, now) do
    challenge == binding.current_challenge or
      ((challenge == binding.previous_challenge and
          binding.previous_challenge_expires_at) &&
         DateTime.compare(binding.previous_challenge_expires_at, now) == :gt)
  end

  defp verify_registration_proof(
         %{header: %{"alg" => "ES256", "typ" => "dbsc+jwt", "jwk" => jwk}} =
           proof
       )
       when is_map(jwk) do
    verify_es256_jws(proof, jwk)
  end

  defp verify_registration_proof(_), do: {:error, :invalid_dbsc_proof}

  defp verify_refresh_proof(
         %{header: %{"alg" => "ES256", "typ" => "dbsc+jwt"} = header} = proof,
         binding
       ) do
    if Map.has_key?(header, "jwk") do
      {:error, :invalid_dbsc_proof}
    else
      verify_es256_jws(proof, binding.public_key_jwk)
    end
  end

  defp verify_refresh_proof(_, _), do: {:error, :invalid_dbsc_proof}

  defp verify_es256_jws(%{signing_input: signing_input, signature: signature}, jwk) do
    with {:ok, public_key} <- jwk_public_key(jwk),
         {:ok, der_signature} <- raw_ecdsa_to_der(signature),
         true <-
           :crypto.verify(:ecdsa, :sha256, signing_input, der_signature, [public_key, :prime256v1]) do
      :ok
    else
      _ -> {:error, :invalid_dbsc_proof}
    end
  end

  defp parse_proof(value) when is_binary(value) do
    value = unwrap_sf_string(value)

    case String.split(value, ".", parts: 3) do
      [encoded_header, encoded_payload, encoded_signature] ->
        with {:ok, header_bytes} <- Base.url_decode64(encoded_header, padding: false),
             {:ok, payload_bytes} <- Base.url_decode64(encoded_payload, padding: false),
             {:ok, signature} <- Base.url_decode64(encoded_signature, padding: false),
             {:ok, header} <- Jason.decode(header_bytes),
             {:ok, payload} <- Jason.decode(payload_bytes),
             true <- is_map(header),
             true <- is_map(payload) do
          {:ok,
           %{
             header: header,
             payload: payload,
             signature: signature,
             signing_input: encoded_header <> "." <> encoded_payload
           }}
        else
          _ -> {:error, :invalid_dbsc_proof}
        end

      _ ->
        {:error, :invalid_dbsc_proof}
    end
  end

  defp parse_proof(_), do: {:error, :invalid_dbsc_proof}

  defp required_claim(payload, key) do
    case Map.get(payload, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_dbsc_claim}
    end
  end

  defp public_jwk!(%{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y})
       when is_binary(x) and is_binary(y),
       do: %{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y}

  defp public_jwk!(_), do: raise(ArgumentError, "invalid DBSC public JWK")

  defp jwk_public_key(%{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y})
       when is_binary(x) and is_binary(y) do
    with {:ok, x} <- Base.url_decode64(x, padding: false),
         {:ok, y} <- Base.url_decode64(y, padding: false),
         32 <- byte_size(x),
         32 <- byte_size(y) do
      {:ok, <<4, x::binary, y::binary>>}
    else
      _ -> {:error, :invalid_dbsc_jwk}
    end
  end

  defp jwk_public_key(_), do: {:error, :invalid_dbsc_jwk}

  defp raw_ecdsa_to_der(<<r::binary-size(32), s::binary-size(32)>>) do
    r = der_integer(r)
    s = der_integer(s)
    sequence = <<0x02, byte_size(r), r::binary, 0x02, byte_size(s), s::binary>>
    {:ok, <<0x30, byte_size(sequence), sequence::binary>>}
  end

  defp raw_ecdsa_to_der(_), do: {:error, :invalid_dbsc_signature}

  defp der_integer(value) do
    value =
      value
      |> :binary.bin_to_list()
      |> Enum.drop_while(&(&1 == 0))
      |> case do
        [] -> [0]
        bytes -> bytes
      end
      |> :binary.list_to_bin()

    case value do
      <<first, _rest::binary>> when first >= 0x80 -> <<0, value::binary>>
      _ -> value
    end
  end

  defp token_hash(token), do: :sha256 |> :crypto.hash(token) |> Base.url_encode64(padding: false)

  defp random_base64url(bytes),
    do: bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  defp unwrap_sf_string(value) do
    value = String.trim(value)

    if String.starts_with?(value, "\"") and String.ends_with?(value, "\"") and
         String.length(value) >= 2 do
      value
      |> String.slice(1, String.length(value) - 2)
      |> String.replace(~s(\\"), ~s("))
      |> String.replace(~s(\\\\), ~s(\\))
    else
      value
    end
  end

  defp sf_string(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end
end
