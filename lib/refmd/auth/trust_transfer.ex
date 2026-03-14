defmodule RefMD.Auth.TrustTransfer do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.{TrustTransferNonce, TrustTransferState}
  alias RefMD.Repo

  @trust_transfer_nonce_ttl 5 * 60
  @trust_transfer_max_payload_bytes 1_048_576

  @spec create_trust_transfer_nonce(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary(), DateTime.t()} | {:error, Ecto.Changeset.t()}
  def create_trust_transfer_nonce(user_id, device_id) do
    nonce = :crypto.strong_rand_bytes(32)
    now = DateTime.utc_now()

    %TrustTransferNonce{created_at: now}
    |> TrustTransferNonce.changeset(%{
      user_id: user_id,
      device_id: device_id,
      nonce: nonce,
      expires_at: DateTime.add(now, @trust_transfer_nonce_ttl, :second)
    })
    |> Repo.insert(
      on_conflict: {:replace, [:nonce, :expires_at, :created_at]},
      conflict_target: [:user_id, :device_id]
    )
    |> case do
      {:ok, record} -> {:ok, record.nonce, record.expires_at}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @spec consume_trust_transfer_nonce(Ecto.UUID.t(), Ecto.UUID.t(), binary()) ::
          :ok | {:error, :invalid_nonce}
  def consume_trust_transfer_nonce(user_id, device_id, transfer_nonce) do
    now = DateTime.utc_now()

    query =
      from(n in TrustTransferNonce,
        where:
          n.user_id == ^user_id and
            n.device_id == ^device_id and
            n.nonce == ^transfer_nonce and
            n.expires_at > ^now
      )

    case Repo.delete_all(query) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_nonce}
    end
  end

  @spec trust_transfer_max_payload_bytes() :: pos_integer()
  def trust_transfer_max_payload_bytes, do: @trust_transfer_max_payload_bytes

  @spec save_trust_transfer_state(map()) ::
          {:ok, TrustTransferState.t()} | {:error, Ecto.Changeset.t()}
  def save_trust_transfer_state(attrs) do
    %TrustTransferState{created_at: DateTime.utc_now()}
    |> TrustTransferState.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:sender_device_id, :ciphertext, :nonce, :signature, :created_at]},
      conflict_target: :device_id
    )
  end

  @spec consume_trust_transfer_state(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, TrustTransferState.t()} | {:error, :not_found}
  def consume_trust_transfer_state(user_id, device_id) do
    Repo.transaction(fn ->
      query =
        from(s in TrustTransferState,
          where: s.user_id == ^user_id and s.device_id == ^device_id,
          lock: "FOR UPDATE"
        )

      case Repo.one(query) do
        nil ->
          Repo.rollback(:not_found)

        state ->
          Repo.delete_all(
            from(s in TrustTransferState,
              where: s.user_id == ^user_id and s.device_id == ^device_id
            )
          )

          state
      end
    end)
  end

  @spec delete_expired_trust_transfer_nonces() :: {non_neg_integer(), nil}
  def delete_expired_trust_transfer_nonces do
    now = DateTime.utc_now()

    from(n in TrustTransferNonce, where: n.expires_at < ^now)
    |> Repo.delete_all()
  end
end
