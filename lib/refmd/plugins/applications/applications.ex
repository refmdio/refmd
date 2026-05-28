defmodule RefMD.Plugins.Applications do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Plugins.{
    Activations,
    Packages,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginPackage,
    Storage,
    UserPluginWorkspacePolicy
  }

  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Workspaces.Workspace

  @spec create(map()) :: {:ok, PluginApplication.t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) when is_map(attrs) do
    attrs =
      attrs
      |> Map.put_new(:application_scope_kind, "workspace")
      |> Map.put_new(:application_mode, "workspace_shared")
      |> Map.put_new(:workspace_policy_result, "allowed")
      |> Map.put_new(:state_head_hash, "GENESIS")
      |> Map.put_new(:consent_epoch, 0)

    %PluginApplication{}
    |> PluginApplication.changeset(attrs)
    |> Repo.insert()
  end

  @spec list(Ecto.UUID.t()) :: [PluginApplication.t()]
  def list(workspace_id) do
    Repo.all(
      from(i in PluginApplication,
        where: i.workspace_id == ^workspace_id and is_nil(i.deleted_at),
        order_by: [asc: i.plugin_id]
      )
    )
  end

  @spec apply_package(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t() | nil) ::
          {:ok, %{application: PluginApplication.t(), activation: PluginActivation.t()}}
          | {:error, Ecto.Changeset.t() | atom()}
  def apply_package(workspace_id, package_id, user_id, device_id) do
    with %PluginPackage{} = package <- Packages.get(package_id),
         :ok <- validate_applicable_package(package, workspace_id, user_id),
         :ok <- validate_package_pinned(package),
         package <- Repo.preload(package, :current_bundle),
         :ok <- validate_user_package_workspace_application_policy(workspace_id, package),
         {:ok, application} <- get_or_create_applied_application(workspace_id, package, user_id),
         {:ok, activation} <-
           get_or_create_application_activation(application, user_id, device_id) do
      {:ok, %{application: application, activation: activation}}
    else
      nil -> {:error, :plugin_package_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec ensure_personal_package_runtime(
          Ecto.UUID.t(),
          PluginPackage.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, %{application: PluginApplication.t(), activation: PluginActivation.t()}}
          | {:error, Ecto.Changeset.t() | atom()}
  def ensure_personal_package_runtime(
        workspace_id,
        %PluginPackage{} = package,
        user_id,
        device_id
      ) do
    with :ok <- validate_personal_package_runtime(package, user_id),
         :ok <- validate_package_pinned(package),
         package <- Repo.preload(package, :current_bundle),
         :ok <- validate_personal_package_workspace_application(package.current_bundle),
         :ok <- validate_personal_package_workspace_policy(workspace_id, package),
         {:ok, application} <- get_or_create_applied_application(workspace_id, package, user_id),
         {:ok, activation} <-
           get_or_create_application_activation(application, user_id, device_id) do
      {:ok, %{application: application, activation: activation}}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @spec ensure_existing_personal_package_runtime(
          Ecto.UUID.t(),
          PluginPackage.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, %{application: PluginApplication.t(), activation: PluginActivation.t()}}
          | {:error, Ecto.Changeset.t() | atom()}
  def ensure_existing_personal_package_runtime(
        workspace_id,
        %PluginPackage{} = package,
        user_id,
        device_id
      ) do
    with :ok <- validate_personal_package_runtime(package, user_id),
         :ok <- validate_package_pinned(package),
         package <- Repo.preload(package, :current_bundle),
         :ok <- validate_user_package_workspace_application_policy(workspace_id, package),
         %PluginApplication{} = application <-
           Repo.get_by(PluginApplication, workspace_id: workspace_id, package_id: package.id),
         {:ok, application} <- sync_application_to_package(application, package),
         {:ok, activation} <-
           get_or_create_application_activation(application, user_id, device_id) do
      {:ok, %{application: application, activation: activation}}
    else
      nil -> {:error, :plugin_application_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec ensure_personal_workspace_applications(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) :: :ok
  def ensure_personal_workspace_applications(workspace_id, user_id, device_id) do
    user_id
    |> Packages.list_for_user()
    |> Repo.preload(:current_bundle)
    |> Enum.each(fn package ->
      case ensure_personal_package_runtime(workspace_id, package, user_id, device_id) do
        {:ok, _result} -> :ok
        {:error, _reason} -> :ok
      end
    end)
  end

  @spec recompute_workspace_user_policy(Ecto.UUID.t()) :: :ok | {:error, term()}
  def recompute_workspace_user_policy(workspace_id) do
    Repo.all(
      from(a in PluginApplication,
        where:
          a.workspace_id == ^workspace_id and a.application_mode == "user_applied" and
            not is_nil(a.current_bundle_id) and is_nil(a.deleted_at),
        preload: [package: :current_bundle],
        order_by: [asc: a.plugin_id]
      )
    )
    |> Enum.reduce_while(:ok, &recompute_workspace_user_policy_application(&1, &2, workspace_id))
  end

  @spec get(Ecto.UUID.t()) :: PluginApplication.t() | nil
  def get(id), do: Repo.get(PluginApplication, id)

  @spec update(PluginApplication.t(), map()) ::
          {:ok, PluginApplication.t()} | {:error, Ecto.Changeset.t()}
  def update(%PluginApplication{} = application, attrs) when is_map(attrs) do
    was_runtime_allowed? = runtime_enabled?(application)

    Repo.transaction(fn ->
      case application
           |> PluginApplication.changeset(Map.take(attrs, [:enabled, :workspace_policy_result]))
           |> Repo.update() do
        {:ok, updated} -> audit_runtime_denied_update(updated, was_runtime_allowed?)
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, updated} -> {:ok, updated}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec delete(PluginApplication.t()) ::
          {:ok, PluginApplication.t()} | {:error, Ecto.Changeset.t()}
  def delete(%PluginApplication{deleted_at: nil} = application) do
    application = preload_current_bundle(application)
    activations = Activations.list_for_application(application.id)
    deleted_at = DateTime.utc_now()

    Repo.transaction(fn ->
      with {:ok, deleted} <-
             application
             |> PluginApplication.changeset(%{
               enabled: false,
               current_bundle_id: nil,
               deleted_at: deleted_at
             })
             |> Repo.update(),
           :ok <- delete_application_activations(activations, deleted_at),
           :ok <- Storage.delete_application_storage(application.id) do
        audit_deleted(deleted, application, activations)
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, deleted} -> {:ok, deleted}
      {:error, reason} -> {:error, reason}
    end
  end

  def delete(%PluginApplication{}), do: {:error, :not_found}

  @spec validate_owner(map(), PluginApplication.t()) ::
          :ok | {:error, :bundle_application_mismatch}
  def validate_owner(attrs, %PluginApplication{} = application) do
    workspace_id = Map.get(attrs, :workspace_id)
    plugin_id = Map.get(attrs, :plugin_id)

    if workspace_id == application.workspace_id and plugin_id == application.plugin_id do
      :ok
    else
      {:error, :bundle_application_mismatch}
    end
  end

  defp preload_current_bundle(%PluginApplication{} = application),
    do: Repo.preload(application, :current_bundle)

  defp validate_applicable_package(
         %PluginPackage{owner_scope_kind: "user", owner_user_id: user_id},
         _workspace_id,
         user_id
       ),
       do: :ok

  defp validate_applicable_package(
         %PluginPackage{owner_scope_kind: "user"},
         _workspace_id,
         _user_id
       ),
       do: {:error, :plugin_package_forbidden}

  defp validate_applicable_package(
         %PluginPackage{owner_scope_kind: "workspace", owner_workspace_id: workspace_id},
         workspace_id,
         _user_id
       ),
       do: :ok

  defp validate_applicable_package(
         %PluginPackage{owner_scope_kind: "workspace"},
         _workspace_id,
         _user_id
       ),
       do: {:error, :plugin_package_forbidden}

  defp validate_applicable_package(%PluginPackage{}, _workspace_id, _user_id),
    do: {:error, :plugin_package_scope_unsupported}

  defp validate_personal_package_runtime(
         %PluginPackage{owner_scope_kind: "user", owner_user_id: user_id},
         user_id
       ),
       do: :ok

  defp validate_personal_package_runtime(%PluginPackage{owner_scope_kind: "user"}, _user_id),
    do: {:error, :plugin_package_forbidden}

  defp validate_personal_package_runtime(%PluginPackage{}, _user_id),
    do: {:error, :plugin_package_scope_unsupported}

  defp validate_package_pinned(%PluginPackage{
         current_bundle_id: bundle_id,
         state_head_hash: hash
       })
       when is_binary(bundle_id) and is_binary(hash) and hash != "GENESIS",
       do: :ok

  defp validate_package_pinned(%PluginPackage{}), do: {:error, :plugin_bundle_not_pinned}

  defp validate_personal_package_workspace_application(%PluginBundle{manifest_json: manifest}) do
    if manifest_workspace_application(manifest) == "none" do
      :ok
    else
      {:error, :plugin_workspace_application_required}
    end
  end

  defp validate_personal_package_workspace_application(_bundle),
    do: {:error, :plugin_bundle_not_pinned}

  defp validate_personal_package_workspace_policy(workspace_id, %PluginPackage{} = package) do
    if workspace_policy_result(workspace_id, package) == "allowed" do
      :ok
    else
      {:error, :plugin_workspace_policy_denied}
    end
  end

  defp validate_user_package_workspace_application_policy(
         workspace_id,
         %PluginPackage{owner_scope_kind: "user"} = package
       ) do
    if workspace_policy_result(workspace_id, package) == "denied" do
      {:error, :plugin_workspace_policy_denied}
    else
      :ok
    end
  end

  defp validate_user_package_workspace_application_policy(_workspace_id, %PluginPackage{}),
    do: :ok

  defp get_or_create_applied_application(workspace_id, package, user_id) do
    case Repo.get_by(PluginApplication, workspace_id: workspace_id, package_id: package.id) do
      %PluginApplication{} = application ->
        sync_application_to_package(application, package)

      nil ->
        create(%{
          package_id: package.id,
          workspace_id: workspace_id,
          plugin_id: package.plugin_id,
          created_by_user_id: user_id,
          application_scope_kind: "workspace",
          application_mode: application_mode(package),
          workspace_policy_result: workspace_policy_result(workspace_id, package),
          current_bundle_id: package.current_bundle_id,
          state_head_hash: package.state_head_hash,
          enabled: true,
          consent_epoch: 0
        })
    end
  end

  defp sync_application_to_package(%PluginApplication{} = application, %PluginPackage{} = package) do
    application
    |> PluginApplication.changeset(%{
      current_bundle_id: package.current_bundle_id,
      state_head_hash: package.state_head_hash,
      workspace_policy_result: synced_workspace_policy_result(application, package),
      enabled: true,
      deleted_at: nil
    })
    |> Repo.update()
  end

  defp synced_workspace_policy_result(
         %PluginApplication{} = application,
         %PluginPackage{} = package
       ) do
    if application.current_bundle_id != package.current_bundle_id ||
         application.state_head_hash != package.state_head_hash do
      workspace_policy_result(application.workspace_id, package)
    else
      application.workspace_policy_result ||
        workspace_policy_result(application.workspace_id, package)
    end
  end

  @spec runtime_allowed?(PluginApplication.t()) :: boolean()
  def runtime_allowed?(%PluginApplication{workspace_policy_result: "allowed"}), do: true
  def runtime_allowed?(%PluginApplication{}), do: false

  @spec validate_runtime_policy(PluginApplication.t()) ::
          :ok | {:error, :plugin_workspace_policy_denied}
  def validate_runtime_policy(%PluginApplication{} = application) do
    if runtime_allowed?(application) do
      :ok
    else
      {:error, :plugin_workspace_policy_denied}
    end
  end

  @spec workspace_policy_result(PluginPackage.t()) :: String.t()
  def workspace_policy_result(%PluginPackage{} = package) do
    workspace_policy_result(package, current_package_bundle(package))
  end

  @spec workspace_policy_result(PluginPackage.t(), PluginBundle.t() | nil) :: String.t()
  def workspace_policy_result(%PluginPackage{owner_scope_kind: "user"} = package, bundle) do
    default_workspace_policy_result(package, bundle)
  end

  def workspace_policy_result(%PluginPackage{}, _bundle), do: "allowed"

  @spec workspace_policy_result(Ecto.UUID.t(), PluginPackage.t()) :: String.t()
  def workspace_policy_result(workspace_id, %PluginPackage{} = package) do
    workspace_policy_result(workspace_id, package, current_package_bundle(package))
  end

  @spec workspace_policy_result(Ecto.UUID.t(), PluginPackage.t(), PluginBundle.t() | nil) ::
          String.t()
  def workspace_policy_result(
        workspace_id,
        %PluginPackage{owner_scope_kind: "user"} = package,
        bundle
      ) do
    admin_approval_required? = user_package_needs_admin_approval?(package, bundle)

    workspace_id
    |> workspace_user_policy()
    |> UserPluginWorkspacePolicy.evaluate(package.plugin_id, admin_approval_required?)
  end

  def workspace_policy_result(_workspace_id, %PluginPackage{} = package, bundle),
    do: workspace_policy_result(package, bundle)

  defp default_workspace_policy_result(%PluginPackage{} = package, bundle) do
    if user_package_needs_admin_approval?(package, bundle),
      do: "needs_admin_review",
      else: "allowed"
  end

  defp application_mode(%PluginPackage{owner_scope_kind: "user"}), do: "user_applied"
  defp application_mode(%PluginPackage{}), do: "workspace_shared"

  defp workspace_user_policy(workspace_id) do
    case Repo.get(Workspace, workspace_id) do
      %Workspace{plugin_user_policy: policy} -> policy
      nil -> nil
    end
  end

  defp user_package_needs_admin_approval?(%PluginPackage{} = package, nil),
    do: package |> current_package_bundle() |> bundle_needs_admin_approval?()

  defp user_package_needs_admin_approval?(%PluginPackage{}, bundle),
    do: bundle_needs_admin_approval?(bundle)

  defp current_package_bundle(%PluginPackage{current_bundle: %PluginBundle{} = bundle}),
    do: bundle

  defp current_package_bundle(%PluginPackage{current_bundle_id: bundle_id})
       when is_binary(bundle_id),
       do: Repo.get(PluginBundle, bundle_id)

  defp current_package_bundle(%PluginPackage{}), do: nil

  defp bundle_needs_admin_approval?(%PluginBundle{manifest_json: manifest})
       when is_map(manifest) do
    permissions = manifest_permissions(manifest)

    Enum.any?(permissions, &permission_needs_admin_review?/1) or
      manifest_has_shared_ui_contribution?(manifest)
  end

  defp bundle_needs_admin_approval?(_bundle), do: true

  defp manifest_permissions(%{"permissions" => permissions}) when is_list(permissions),
    do: Enum.filter(permissions, &is_binary/1)

  defp manifest_permissions(_manifest), do: []

  defp permission_needs_admin_review?(permission) do
    String.starts_with?(permission, "document:") or
      String.starts_with?(permission, "plaintext:") or
      String.starts_with?(permission, "editor:") or
      String.starts_with?(permission, "credential:") or
      String.starts_with?(permission, "ui:") or
      permission == "network:fetch" or
      permission == "storage:write:workspace" or
      permission == "storage:read:workspace"
  end

  defp manifest_has_shared_ui_contribution?(manifest) do
    non_empty_list?(Map.get(manifest, "rendererSlots")) or
      non_empty_list?(Map.get(manifest, "menus")) or
      non_empty_list?(Map.get(manifest, "commands")) or
      non_empty_list?(Map.get(manifest, "statusItems")) or
      non_empty_list?(Map.get(manifest, "settings"))
  end

  defp non_empty_list?(value), do: is_list(value) and value != []

  defp manifest_workspace_application(%{"scope" => %{"workspaceApplication" => value}})
       when is_binary(value),
       do: value

  defp manifest_workspace_application(_manifest), do: "required"

  defp get_or_create_application_activation(application, user_id, device_id) do
    case Activations.latest(application.id, user_id, device_id) do
      %PluginActivation{} = activation ->
        {:ok, activation}

      nil ->
        Activations.create(%{
          application_id: application.id,
          user_id: user_id,
          device_id: device_id,
          activation_scope_kind: if(is_binary(device_id), do: "device", else: "user"),
          enabled: true
        })
    end
  end

  defp audit_runtime_denied_update(updated, true) do
    if runtime_enabled?(updated) do
      updated
    else
      updated
      |> preload_current_bundle()
      |> Security.record_plugin_application_disabled()
      |> audit_result_or_rollback(updated)
    end
  end

  defp audit_runtime_denied_update(updated, false), do: updated

  defp update_policy_result(application, next_result, was_runtime_allowed?) do
    application
    |> PluginApplication.changeset(%{workspace_policy_result: next_result})
    |> Repo.update()
    |> case do
      {:ok, updated} -> {:ok, audit_runtime_denied_update(updated, was_runtime_allowed?)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp recompute_workspace_user_policy_application(application, :ok, workspace_id) do
    package = application.package
    bundle = current_package_bundle(package)
    next_result = workspace_policy_result(workspace_id, package, bundle)

    application
    |> maybe_update_recomputed_policy(next_result)
    |> case do
      :ok -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp maybe_update_recomputed_policy(application, next_result) do
    if application.workspace_policy_result == next_result do
      :ok
    else
      application
      |> update_policy_result(next_result, runtime_enabled?(application))
      |> case do
        {:ok, _updated} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp runtime_enabled?(%PluginApplication{} = application) do
    is_nil(application.deleted_at) and application.enabled and runtime_allowed?(application)
  end

  defp delete_application_activations(activations, deleted_at) do
    activations
    |> Enum.filter(&is_nil(&1.deleted_at))
    |> Enum.reduce_while(:ok, fn activation, :ok ->
      case activation
           |> PluginActivation.changeset(%{enabled: false, deleted_at: deleted_at})
           |> Repo.update() do
        {:ok, _deleted} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp audit_deleted(deleted, application, activations) do
    application
    |> Security.record_plugin_application_uninstalled(activations)
    |> audit_result_or_rollback(deleted)
  end

  defp audit_result_or_rollback({:ok, _}, value), do: value
  defp audit_result_or_rollback({:error, reason}, _value), do: Repo.rollback(reason)
end
