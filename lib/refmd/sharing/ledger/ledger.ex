defmodule RefMD.Sharing.Ledger do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Repo
  alias RefMD.Sharing.{Share, ShareOpenConsumption}

  @max_safe_integer 9_007_199_254_740_991

  @spec consume!(Share.t(), String.t(), Ecto.UUID.t()) :: :ok | no_return()
  def consume!(%Share{} = share, consumer_kind, consumer_id)
      when is_binary(consumer_kind) and is_binary(consumer_id) do
    case Repo.transaction(fn -> consume_locked!(share, consumer_kind, consumer_id) end) do
      {:ok, :ok} -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  @spec record_existing_open(Share.t(), String.t(), Ecto.UUID.t()) :: :ok | {:error, term()}
  def record_existing_open(%Share{} = share, consumer_kind, consumer_id)
      when is_binary(consumer_kind) and is_binary(consumer_id) do
    case Repo.transaction(fn ->
           record_existing_open_locked!(share, consumer_kind, consumer_id)
         end) do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @spec consumed?(Ecto.UUID.t(), String.t(), Ecto.UUID.t()) :: boolean()
  def consumed?(share_id, consumer_kind, consumer_id)
      when is_binary(share_id) and is_binary(consumer_kind) and is_binary(consumer_id) do
    from(c in ShareOpenConsumption,
      where:
        c.share_id == ^share_id and c.consumer_kind == ^consumer_kind and
          c.consumer_id == ^consumer_id
    )
    |> Repo.exists?()
  end

  defp consume_locked!(%Share{id: share_id}, consumer_kind, consumer_id) do
    share =
      from(s in Share, where: s.id == ^share_id, lock: "FOR UPDATE")
      |> Repo.one()

    if is_nil(share), do: Repo.rollback(:not_found)

    if consumed?(share.id, consumer_kind, consumer_id) do
      :ok
    else
      insert_consumption!(share, consumer_kind, consumer_id)
      refresh_view_count!(share.id)
    end
  end

  defp record_existing_open_locked!(%Share{id: share_id}, consumer_kind, consumer_id) do
    share =
      from(s in Share, where: s.id == ^share_id, lock: "FOR UPDATE")
      |> Repo.one()

    if is_nil(share), do: Repo.rollback(:not_found)

    if consumed?(share.id, consumer_kind, consumer_id) do
      :ok
    else
      insert_open_consumption!(share, consumer_kind, consumer_id)
      refresh_view_count!(share.id)
    end
  end

  defp insert_consumption!(%Share{} = share, consumer_kind, consumer_id) do
    count = ledger_count(share.id)

    if share.max_views != @max_safe_integer and count >= share.max_views do
      Repo.rollback(:not_found)
    end

    insert_open_consumption!(share, consumer_kind, consumer_id)
  end

  defp insert_open_consumption!(%Share{} = share, consumer_kind, consumer_id) do
    %ShareOpenConsumption{}
    |> ShareOpenConsumption.changeset(%{
      share_id: share.id,
      consumer_kind: consumer_kind,
      consumer_id: consumer_id,
      consumed_at: DateTime.utc_now()
    })
    |> Repo.insert!()
  rescue
    Ecto.ConstraintError -> :ok
  end

  defp refresh_view_count!(share_id) do
    count = ledger_count(share_id)

    {updated, _rows} =
      from(s in Share, where: s.id == ^share_id)
      |> Repo.update_all(set: [view_count: count])

    if updated == 1, do: :ok, else: Repo.rollback(:not_found)
  end

  defp ledger_count(share_id) do
    from(c in ShareOpenConsumption,
      where: c.share_id == ^share_id,
      select: count(c.id)
    )
    |> Repo.one()
  end
end
