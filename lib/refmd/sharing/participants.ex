defmodule RefMD.Sharing.Participants do
  @moduledoc """
  Participant sessions, devices, PoP challenges, and websocket tokens.
  """

  import Ecto.Query

  alias RefMD.Repo

  alias RefMD.Sharing.{
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

  @spec create_participant_session(Share.t(), binary(), binary(), binary()) :: map()
  def create_participant_session(share, display_name, signing_key, encryption_key) do
    principal_device =
      find_or_create_participant_device(share.id, display_name, signing_key, encryption_key)

    increment_access_count!(share)
    {raw_token, token_hash} = generate_session_token()
    now = DateTime.utc_now()

    session_changeset =
      %ShareParticipantSession{created_at: now}
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
          participant: %{
            principal_id: principal_device.principal.id,
            device_id: principal_device.device.id,
            grant: share.permission
          },
          session: session,
          session_token: raw_token
        }

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
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
      where: d.id == ^device_id and d.principal_id == ^principal_id
    )
    |> Repo.exists?()
  end

  @spec get_participant_device(Ecto.UUID.t()) :: ShareParticipantDevice.t() | nil
  def get_participant_device(device_id), do: Repo.get(ShareParticipantDevice, device_id)

  @spec create_pop_challenge(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, Ecto.Changeset.t()}
  def create_pop_challenge(share_id, device_id) do
    challenge = :crypto.strong_rand_bytes(32)
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    case %ShareParticipantPopChallenge{created_at: now}
         |> ShareParticipantPopChallenge.changeset(%{
           share_id: share_id,
           device_id: device_id,
           challenge_hash: challenge_hash,
           expires_at: DateTime.add(now, @share_pop_challenge_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _challenge} -> {:ok, challenge}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @spec consume_pop_challenge(binary(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, :invalid_challenge}
  def consume_pop_challenge(challenge, share_id, device_id) do
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    query =
      from(pc in ShareParticipantPopChallenge,
        where:
          pc.challenge_hash == ^challenge_hash and
            pc.share_id == ^share_id and
            pc.device_id == ^device_id and
            pc.expires_at > ^now
      )

    case Repo.delete_all(query) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_challenge}
    end
  end

  @spec generate_ws_token(Ecto.UUID.t()) :: String.t()
  def generate_ws_token(session_id) do
    Phoenix.Token.sign(RefMDWeb.Endpoint, @ws_token_salt, session_id)
  end

  @spec verify_ws_token(String.t()) ::
          {:ok, Ecto.UUID.t(), ShareParticipantSession.t()} | {:error, atom()}
  def verify_ws_token(token) do
    with {:ok, session_id} <-
           Phoenix.Token.verify(RefMDWeb.Endpoint, @ws_token_salt, token,
             max_age: @ws_token_max_age
           ),
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
        where: s.token_hash == ^token_hash and s.expires_at > ^now
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
        where: s.id == ^session_id and s.expires_at > ^now
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

  defp find_or_create_participant_device(share_id, display_name, signing_key, encryption_key) do
    now = DateTime.utc_now()

    existing =
      from(d in ShareParticipantDevice,
        join: p in ShareParticipantPrincipal,
        on: p.id == d.principal_id,
        where: d.share_id == ^share_id and d.signing_public_key == ^signing_key,
        select: %{device: d, principal: p},
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    case existing do
      %{device: device, principal: principal} ->
        Repo.update_all(
          from(d in ShareParticipantDevice, where: d.id == ^device.id),
          set: [last_seen_at: now]
        )

        %{
          device: %{device | last_seen_at: now},
          principal: principal
        }

      nil ->
        principal =
          %ShareParticipantPrincipal{}
          |> ShareParticipantPrincipal.changeset(%{
            share_id: share_id,
            display_name: display_name
          })
          |> Repo.insert!()

        device =
          %ShareParticipantDevice{}
          |> ShareParticipantDevice.changeset(%{
            share_id: share_id,
            principal_id: principal.id,
            signing_public_key: signing_key,
            encryption_public_key: encryption_key,
            last_seen_at: now
          })
          |> Repo.insert!()

        %{device: device, principal: principal}
    end
  end

  defp increment_access_count!(%Share{access_limit: nil} = share) do
    {updated, _rows} =
      from(s in Share,
        where: s.id == ^share.id,
        select: %{id: s.id}
      )
      |> Repo.update_all(inc: [access_count: 1])

    if updated == 1, do: :ok, else: Repo.rollback(:not_found)
  end

  defp increment_access_count!(%Share{} = share) do
    {updated, _rows} =
      from(s in Share,
        where: s.id == ^share.id and (is_nil(s.access_limit) or s.access_count < s.access_limit),
        select: %{id: s.id}
      )
      |> Repo.update_all(inc: [access_count: 1])

    if updated == 0 do
      Repo.rollback(:not_found)
    end

    :ok
  end

  defp generate_session_token do
    raw = :crypto.strong_rand_bytes(32)
    {raw, Base.url_encode64(:crypto.hash(:sha256, raw), padding: false)}
  end
end
