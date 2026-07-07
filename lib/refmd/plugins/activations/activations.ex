defmodule RefMD.Plugins.Activations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Plugins.PluginActivation
  alias RefMD.Plugins.PluginApplication
  alias RefMD.Repo
  alias RefMD.Security

  def create(attrs) when is_map(attrs) do
    %PluginActivation{}
    |> PluginActivation.changeset(attrs)
    |> Repo.insert()
  end

  def get_or_create_application(application_id, user_id, device_id) do
    case latest(application_id, user_id, device_id) do
      %PluginActivation{} = activation ->
        {:ok, activation}

      nil ->
        create(%{
          application_id: application_id,
          user_id: user_id,
          device_id: device_id,
          activation_scope_kind: if(is_binary(device_id), do: "device", else: "user"),
          enabled: true
        })
    end
  end

  def list_for_actor(user_id, device_id) do
    Repo.all(
      from(a in PluginActivation,
        join: application in PluginApplication,
        on: application.id == a.application_id,
        where:
          a.user_id == ^user_id and
            (is_nil(a.device_id) or a.device_id == ^device_id) and is_nil(a.deleted_at),
        where: is_nil(application.deleted_at),
        order_by: [desc: a.created_at]
      )
    )
  end

  def list_for_application(application_id) do
    Repo.all(
      from(a in PluginActivation,
        where: a.application_id == ^application_id,
        order_by: [desc: :created_at]
      )
    )
  end

  def get(id) do
    case Ecto.UUID.cast(id) do
      {:ok, uuid} -> Repo.get(PluginActivation, uuid)
      :error -> nil
    end
  end

  def get_active(id) do
    case get(id) do
      %PluginActivation{deleted_at: nil} = activation -> activation
      %PluginActivation{} -> nil
      nil -> nil
    end
  end

  def update(%PluginActivation{} = activation, attrs, opts \\ []) when is_map(attrs) do
    if activation.deleted_at do
      {:error, :not_found}
    else
      do_update(activation, attrs, opts)
    end
  end

  defp do_update(%PluginActivation{} = activation, attrs, opts) do
    was_enabled = activation.enabled
    actor_device_id = Keyword.get(opts, :actor_device_id)

    Repo.transaction(fn ->
      case activation
           |> PluginActivation.changeset(Map.take(attrs, [:enabled]))
           |> Repo.update() do
        {:ok, updated} -> audit_disabled_update(updated, was_enabled, actor_device_id)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, updated} -> {:ok, updated}
      {:error, reason} -> {:error, reason}
    end
  end

  def delete(activation, opts \\ [])

  def delete(%PluginActivation{deleted_at: nil} = activation, opts) do
    actor_device_id = Keyword.get(opts, :actor_device_id)
    deleted_at = DateTime.utc_now()

    Repo.transaction(fn ->
      case activation
           |> PluginActivation.changeset(%{enabled: false, deleted_at: deleted_at})
           |> Repo.update() do
        {:ok, deleted} ->
          deleted
          |> Security.record_plugin_activation_deleted(actor_device_id || deleted.device_id)
          |> audit_result_or_rollback(deleted)

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, deleted} -> {:ok, deleted}
      {:error, reason} -> {:error, reason}
    end
  end

  def delete(%PluginActivation{}, _opts), do: {:error, :not_found}

  def latest(application_id, user_id, device_id) do
    Repo.one(
      from(a in PluginActivation,
        where:
          a.application_id == ^application_id and a.user_id == ^user_id and
            (a.device_id == ^device_id or is_nil(a.device_id)) and is_nil(a.deleted_at),
        order_by: [desc: a.created_at],
        limit: 1
      )
    )
  end

  def latest_for_actor(application_id, user_id, device_id) do
    Repo.one(
      from(a in PluginActivation,
        where:
          a.application_id == ^application_id and a.user_id == ^user_id and
            (a.device_id == ^device_id or is_nil(a.device_id)),
        order_by: [desc: a.created_at],
        limit: 1
      )
    )
  end

  defp audit_disabled_update(updated, true, actor_device_id) do
    if updated.enabled == false do
      updated
      |> Security.record_plugin_activation_disabled(actor_device_id || updated.device_id)
      |> audit_result_or_rollback(updated)
    else
      updated
    end
  end

  defp audit_disabled_update(updated, false, _actor_device_id), do: updated

  defp audit_result_or_rollback({:ok, _}, value), do: value
  defp audit_result_or_rollback({:error, reason}, _value), do: Repo.rollback(reason)
end
