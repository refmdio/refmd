defmodule RefMD.Sharing.Participants do
  @moduledoc """
  Participant sessions, devices, PoP challenges, and websocket tokens.
  """

  import Ecto.Query

  alias RefMD.Crypto.{Hash, Signature, TokenSigning}
  alias RefMD.Repo

  alias RefMD.Sharing.{
    Access,
    Share,
    SharedDocumentToken,
    SharedFolderToken,
    ShareParticipantDevice,
    ShareParticipantPopChallenge,
    ShareParticipantPrincipal,
    ShareParticipantSession
  }

  @share_session_ttl 24 * 60 * 60
  @share_pop_challenge_ttl 5 * 60
  @ws_token_salt "share_ws_auth_token"
  @ws_token_max_age 300
  @max_safe_integer 9_007_199_254_740_991

  @spec create_participant_session(Share.t(), map()) :: map()
  def create_participant_session(share, authorization) do
    unless share_accepting_new_participant?(share) do
      Repo.rollback(:not_found)
    end

    principal_device =
      find_or_create_participant_device(
        share,
        authorization
      )

    {raw_token, token_hash} = generate_session_token()
    now = DateTime.utc_now()

    session_changeset =
      %ShareParticipantSession{id: authorization.session_id, created_at: now}
      |> ShareParticipantSession.changeset(%{
        share_id: share.id,
        principal_id: principal_device.principal.id,
        device_id: principal_device.device.id,
        grant: share.permission,
        token_hash: token_hash,
        expires_at: DateTime.add(now, @share_session_ttl, :second),
        last_seen_at: now
      })

    case Repo.insert(session_changeset) do
      {:ok, session} ->
        root = get_share_root!(share)

        %{
          root: root,
          share_id: share.id,
          scope_kind: share.scope,
          scope_id: share.document_id,
          created_event_hash: share.created_event_hash,
          latest_bootstrap_event_hash: share.latest_bootstrap_event_hash,
          capability_context_hash: share.capability_context_hash,
          share_capability_secret_commitment: share.share_capability_secret_commitment,
          password_capability_secret_commitment: share.password_capability_secret_commitment,
          participant: %{
            principal_id: principal_device.principal.id,
            device_id: principal_device.device.id,
            session_id: session.id,
            grant: share.permission
          },
          session: session,
          session_token: raw_token
        }

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  @spec resume_participant_session(Share.t(), ShareParticipantSession.t(), String.t()) :: map()
  def resume_participant_session(
        %Share{} = share,
        %ShareParticipantSession{} = session,
        token_base64
      )
      when is_binary(token_base64) do
    now = DateTime.utc_now()

    participant =
      from(d in ShareParticipantDevice,
        join: p in ShareParticipantPrincipal,
        on: p.id == d.principal_id,
        where:
          d.id == ^session.device_id and d.share_id == ^share.id and
            p.id == ^session.principal_id and
            p.share_id == ^share.id and is_nil(d.revoked_at),
        select: %{device: d, principal: p},
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    unless participant do
      Repo.rollback(:not_found)
    end

    Repo.update_all(
      from(d in ShareParticipantDevice,
        where: d.id == ^session.device_id and d.share_id == ^share.id
      ),
      set: [last_seen_at: now]
    )

    raw_token =
      case Base.url_decode64(token_base64, padding: false) do
        {:ok, token} -> token
        :error -> Repo.rollback(:invalid_token)
      end

    updated_session =
      session
      |> ShareParticipantSession.changeset(%{
        share_id: share.id,
        principal_id: session.principal_id,
        device_id: session.device_id,
        grant: share.permission,
        token_hash: session.token_hash,
        expires_at: DateTime.add(now, @share_session_ttl, :second),
        last_seen_at: now
      })
      |> Repo.update!()

    %{
      participant: %{
        principal_id: session.principal_id,
        device_id: session.device_id,
        session_id: updated_session.id,
        grant: share.permission
      },
      session: updated_session,
      session_token: raw_token
    }
  end

  @spec get_valid_participant_session_by_token_base64(String.t() | nil) ::
          {:ok, ShareParticipantSession.t()} | {:error, :invalid_session | :invalid_token}
  def get_valid_participant_session_by_token_base64(token_base64) when is_binary(token_base64) do
    case Base.url_decode64(token_base64, padding: false) do
      {:ok, raw_token} -> get_valid_participant_session(raw_token)
      :error -> {:error, :invalid_token}
    end
  end

  def get_valid_participant_session_by_token_base64(_), do: {:error, :invalid_token}

  @spec touch_participant_session(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def touch_participant_session(session_id) do
    from(s in ShareParticipantSession, where: s.id == ^session_id)
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  @spec delete_participant_session(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_participant_session(session_id) do
    from(s in ShareParticipantSession, where: s.id == ^session_id)
    |> Repo.delete_all()
  end

  @spec participant_session_active?(Ecto.UUID.t()) :: boolean()
  def participant_session_active?(session_id) do
    match?({:ok, _session}, get_valid_participant_session_by_id(session_id))
  end

  @spec participant_owns_device?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def participant_owns_device?(principal_id, device_id) do
    from(d in ShareParticipantDevice,
      where: d.id == ^device_id and d.principal_id == ^principal_id and is_nil(d.revoked_at)
    )
    |> Repo.exists?()
  end

  @spec lock_participant_device_active(Ecto.UUID.t(), Ecto.UUID.t()) :: :ok | {:error, :not_found}
  def lock_participant_device_active(principal_id, device_id)
      when is_binary(principal_id) and is_binary(device_id) do
    from(d in ShareParticipantDevice,
      where: d.id == ^device_id and d.principal_id == ^principal_id and is_nil(d.revoked_at),
      lock: "FOR SHARE"
    )
    |> Repo.exists?()
    |> case do
      true -> :ok
      false -> {:error, :not_found}
    end
  end

  def lock_participant_device_active(_, _), do: {:error, :not_found}

  @spec share_accepting_new_participant?(Share.t()) :: boolean()
  def share_accepting_new_participant?(%Share{} = share) do
    Access.share_session_accessible?(share) and participant_admission_available?(share)
  end

  @spec participant_admission_available?(Share.t()) :: boolean()
  def participant_admission_available?(%Share{max_views: @max_safe_integer}), do: true

  def participant_admission_available?(%Share{} = share) do
    max(share.view_count || 0, active_participant_device_count(share.id)) < share.max_views
  end

  @spec participant_signing_public_material(Ecto.UUID.t()) :: {:ok, map()} | {:error, :not_found}
  def participant_signing_public_material(device_id) when is_binary(device_id) do
    from(d in ShareParticipantDevice,
      where: d.id == ^device_id and is_nil(d.revoked_at),
      select: d.hybrid_signing_public_key_material
    )
    |> Repo.one()
    |> case do
      material when is_map(material) -> {:ok, material}
      _ -> {:error, :not_found}
    end
  end

  def participant_signing_public_material(_), do: {:error, :not_found}

  @spec share_participant_signer(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, %{device_id: Ecto.UUID.t(), hybrid_signing_public_key_material: map()}}
          | {:error, :not_found}
  def share_participant_signer(share_id, principal_id, device_id)
      when is_binary(share_id) and is_binary(principal_id) and is_binary(device_id) do
    from(d in ShareParticipantDevice,
      where:
        d.id == ^device_id and d.share_id == ^share_id and d.principal_id == ^principal_id and
          is_nil(d.revoked_at),
      select: %{
        device_id: d.id,
        hybrid_signing_public_key_material: d.hybrid_signing_public_key_material
      }
    )
    |> Repo.one()
    |> case do
      %{hybrid_signing_public_key_material: material} = signer when is_map(material) ->
        {:ok, signer}

      _ ->
        {:error, :not_found}
    end
  end

  def share_participant_signer(_, _, _), do: {:error, :not_found}

  @spec get_participant_device(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          ShareParticipantDevice.t() | nil
  def get_participant_device(share_id, principal_id, device_id) do
    from(d in ShareParticipantDevice,
      where:
        d.id == ^device_id and d.share_id == ^share_id and d.principal_id == ^principal_id and
          is_nil(d.revoked_at)
    )
    |> Repo.one()
  end

  @spec validate_share_participant_writer_admission(map()) ::
          {:ok, %{hybrid_signing_public_key_material: map()}}
          | {:error, :invalid_share_participant_writer}
  def validate_share_participant_writer_admission(%{
        share_id: share_id,
        principal_id: principal_id,
        device_id: device_id,
        session_id: session_id,
        signing_key_id: signing_key_id,
        document_id: document_id
      })
      when is_binary(share_id) and is_binary(principal_id) and is_binary(device_id) and
             is_binary(session_id) and is_binary(signing_key_id) and is_binary(document_id) do
    with {:ok, session} <- get_valid_participant_session_by_id(session_id),
         true <- session.share_id == share_id,
         true <- session.principal_id == principal_id,
         true <- session.device_id == device_id,
         true <- session.grant == "edit",
         true <- Access.can_write_document?(share_id, document_id),
         %ShareParticipantDevice{
           share_id: ^share_id,
           principal_id: ^principal_id,
           signing_key_id: ^signing_key_id,
           revoked_at: nil
         } = device <- get_participant_device(share_id, principal_id, device_id) do
      {:ok, %{hybrid_signing_public_key_material: device.hybrid_signing_public_key_material}}
    else
      _ -> {:error, :invalid_share_participant_writer}
    end
  end

  def validate_share_participant_writer_admission(_),
    do: {:error, :invalid_share_participant_writer}

  @spec create_pop_challenge(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, Ecto.Changeset.t()}
  def create_pop_challenge(share_id, principal_id, device_id, session_id) do
    challenge = :crypto.strong_rand_bytes(32)
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    case %ShareParticipantPopChallenge{created_at: now}
         |> ShareParticipantPopChallenge.changeset(%{
           share_id: share_id,
           device_id: device_id,
           challenge_hash: challenge_hash,
           session_id_hash: Hash.blake3_base64url(session_id),
           session_kind: "share_participant",
           subject_id: principal_id,
           share_participant_principal_id: principal_id,
           share_participant_device_id: device_id,
           expires_at: DateTime.add(now, @share_pop_challenge_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _challenge} -> {:ok, challenge}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @spec consume_pop_challenge(
          binary(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t()
        ) ::
          :ok | {:error, :invalid_challenge}
  def consume_pop_challenge(challenge, share_id, principal_id, device_id, session_id) do
    challenge_hash = :crypto.hash(:sha256, challenge)
    session_id_hash = Hash.blake3_base64url(session_id)

    case Repo.delete_all(
           pop_challenge_consumption_query(
             challenge_hash,
             share_id,
             principal_id,
             device_id,
             session_id_hash
           )
         ) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_challenge}
    end
  end

  defp pop_challenge_consumption_query(
         challenge_hash,
         share_id,
         principal_id,
         device_id,
         session_id_hash
       ) do
    now = DateTime.utc_now()

    from(pc in ShareParticipantPopChallenge,
      where: pc.challenge_hash == ^challenge_hash,
      where: pc.session_kind == "share_participant",
      where: pc.subject_id == ^principal_id,
      where: pc.share_id == ^share_id,
      where: pc.device_id == ^device_id,
      where: pc.share_participant_principal_id == ^principal_id,
      where: pc.share_participant_device_id == ^device_id,
      where: pc.session_id_hash == ^session_id_hash,
      where: pc.expires_at > ^now
    )
  end

  @spec generate_ws_token(Ecto.UUID.t()) :: String.t()
  def generate_ws_token(session_id) do
    TokenSigning.sign(@ws_token_salt, session_id)
  end

  @spec verify_ws_token(String.t()) ::
          {:ok, Ecto.UUID.t(), ShareParticipantSession.t()} | {:error, atom()}
  def verify_ws_token(token) do
    with {:ok, session_id} <-
           TokenSigning.verify(@ws_token_salt, token, max_age: @ws_token_max_age),
         %ShareParticipantSession{} = session <- Repo.get(ShareParticipantSession, session_id),
         {:ok, valid_session} <- get_valid_participant_session_by_id(session.id) do
      {:ok, valid_session.principal_id, valid_session}
    else
      nil -> {:error, :invalid_session}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec get_valid_participant_session(binary()) ::
          {:ok, ShareParticipantSession.t()} | {:error, :invalid_session}
  def get_valid_participant_session(raw_token) do
    token_hash = Base.url_encode64(:crypto.hash(:sha256, raw_token), padding: false)
    now = DateTime.utc_now()

    session =
      from(s in ShareParticipantSession,
        join: d in ShareParticipantDevice,
        on: d.id == s.device_id,
        where: s.token_hash == ^token_hash and s.expires_at > ^now and is_nil(d.revoked_at)
      )
      |> Repo.one()

    case session do
      nil -> {:error, :invalid_session}
      %ShareParticipantSession{} = valid_session -> {:ok, valid_session}
    end
  end

  @spec get_valid_participant_session_by_id(Ecto.UUID.t()) ::
          {:ok, ShareParticipantSession.t()} | {:error, :invalid_session}
  def get_valid_participant_session_by_id(session_id) do
    now = DateTime.utc_now()

    session =
      from(s in ShareParticipantSession,
        join: d in ShareParticipantDevice,
        on: d.id == s.device_id,
        where: s.id == ^session_id and s.expires_at > ^now and is_nil(d.revoked_at)
      )
      |> Repo.one()

    case session do
      nil -> {:error, :invalid_session}
      %ShareParticipantSession{} = valid_session -> {:ok, valid_session}
    end
  end

  defp get_root_document_token(share_id, document_id) do
    from(t in SharedDocumentToken,
      where: t.share_id == ^share_id and t.document_id == ^document_id
    )
    |> Repo.one()
  end

  defp get_root_folder_token(share_id, document_id) do
    from(t in SharedFolderToken,
      where: t.share_id == ^share_id and t.document_id == ^document_id
    )
    |> Repo.one()
  end

  defp get_share_root(%Share{scope: "document"} = share) do
    case get_root_document_token(share.id, share.document_id) do
      %SharedDocumentToken{} = token -> {:ok, %{kind: "document", document_token: token.token}}
      nil -> {:error, :not_found}
    end
  end

  defp get_share_root(%Share{scope: "folder"} = share) do
    case get_root_folder_token(share.id, share.document_id) do
      %SharedFolderToken{} = token -> {:ok, %{kind: "folder", folder_token: token.token}}
      nil -> {:error, :not_found}
    end
  end

  defp get_share_root!(share) do
    case get_share_root(share) do
      {:ok, root} -> root
      {:error, :not_found} -> raise "missing root shared token for share #{share.id}"
    end
  end

  defp find_or_create_participant_device(%Share{} = share, authorization) do
    %{
      display_name: display_name,
      device_id: device_id,
      principal_id: principal_id,
      hybrid_signing_public_key_material: hybrid_signing_public_key_material,
      hybrid_encryption_public_key_material: hybrid_encryption_public_key_material
    } = authorization

    share_id = share.id
    now = DateTime.utc_now()
    signing_key_id = Signature.compute_signing_key_id!(hybrid_signing_public_key_material)

    cond do
      lock_participant_device_by_id(device_id) ->
        Repo.rollback(:participant_device_id_reused)

      lock_participant_principal_by_id(principal_id) ->
        Repo.rollback(:participant_principal_id_reused)

      lock_participant_session_by_id(authorization.session_id) ->
        Repo.rollback(:participant_session_id_reused)

      true ->
        create_participant_device!(
          share_id,
          display_name,
          principal_id,
          device_id,
          signing_key_id,
          hybrid_signing_public_key_material,
          hybrid_encryption_public_key_material,
          now
        )
    end
  end

  defp create_participant_device!(
         share_id,
         display_name,
         principal_id,
         device_id,
         signing_key_id,
         hybrid_signing_public_key_material,
         hybrid_encryption_public_key_material,
         now
       ) do
    if share_participant_signing_key_exists?(share_id, signing_key_id) do
      Repo.rollback(:participant_signing_key_reused)
    end

    principal =
      %ShareParticipantPrincipal{}
      |> ShareParticipantPrincipal.changeset(%{
        id: principal_id,
        share_id: share_id,
        display_name: display_name
      })
      |> Repo.insert!()

    device =
      %ShareParticipantDevice{}
      |> ShareParticipantDevice.changeset(%{
        id: device_id,
        share_id: share_id,
        principal_id: principal.id,
        hybrid_signing_public_key_material: hybrid_signing_public_key_material,
        signing_key_id: signing_key_id,
        hybrid_encryption_public_key_material: hybrid_encryption_public_key_material,
        last_seen_at: now
      })
      |> Repo.insert!()

    %{device: device, principal: principal}
  end

  defp lock_participant_device_by_id(device_id) do
    from(d in ShareParticipantDevice,
      where: d.id == ^device_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp lock_participant_principal_by_id(principal_id) do
    from(p in ShareParticipantPrincipal,
      where: p.id == ^principal_id,
      lock: "FOR UPDATE"
    )
    |> Repo.exists?()
  end

  defp lock_participant_session_by_id(session_id) do
    from(s in ShareParticipantSession,
      where: s.id == ^session_id,
      lock: "FOR UPDATE"
    )
    |> Repo.exists?()
  end

  defp active_participant_device_count(share_id) do
    from(d in ShareParticipantDevice,
      where: d.share_id == ^share_id and is_nil(d.revoked_at),
      select: count(d.id)
    )
    |> Repo.one()
  end

  defp share_participant_signing_key_exists?(share_id, signing_key_id) do
    from(d in ShareParticipantDevice,
      where: d.share_id == ^share_id and d.signing_key_id == ^signing_key_id,
      select: true,
      limit: 1
    )
    |> Repo.exists?()
  end

  defp generate_session_token do
    raw = :crypto.strong_rand_bytes(32)
    {raw, Base.url_encode64(:crypto.hash(:sha256, raw), padding: false)}
  end
end
