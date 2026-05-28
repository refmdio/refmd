defmodule RefMD.Plugins.Storage do
  @moduledoc """
  Plugin storage persistence, authorization, and AAD construction.
  """

  import Ecto.Query

  alias RefMD.Documents

  alias RefMD.Plugins.{
    Applications,
    Bundles,
    Consent,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginConsentEvent,
    PluginKV,
    PluginRecord,
    RuntimeAudit,
    RuntimeDescriptors,
    SandboxDocuments
  }

  alias RefMD.Repo
  alias RefMD.Security

  @type storage_scope :: :document | :workspace | String.t()
  @type authorization_attrs :: %{
          optional(:application_id) => Ecto.UUID.t() | String.t() | nil,
          optional(:plugin_id) => String.t() | nil,
          optional(:workspace_id) => Ecto.UUID.t() | String.t(),
          optional(:surface) => String.t(),
          optional(:scope_id) => String.t(),
          optional(:operation) => String.t(),
          optional(:user_id) => Ecto.UUID.t() | String.t(),
          optional(:device_id) => Ecto.UUID.t() | String.t() | nil,
          optional(:state_head_hash) => String.t() | nil,
          optional(:consent_head_hash) => String.t() | nil,
          optional(:capability_grant_id) => String.t() | nil,
          optional(:consent_epoch) => integer() | String.t() | nil,
          optional(:frame_generation) => integer() | String.t() | nil
        }
  @type authorization_context :: %{
          application: PluginApplication.t(),
          activation: PluginActivation.t(),
          bundle: PluginBundle.t(),
          consent: PluginConsentEvent.t(),
          state_head_hash: String.t(),
          consent_head_hash: String.t(),
          capability_grant_id: String.t(),
          consent_epoch: pos_integer(),
          frame_generation: pos_integer()
        }

  @spec authorize_context(authorization_attrs()) ::
          {:ok, authorization_context()} | {:error, atom(), String.t()}
  def authorize_context(attrs) when is_map(attrs) do
    with {:ok, application} <- fetch_authorization_application(attrs),
         :ok <- validate_authorization_document_scope(attrs),
         {:ok, device_id} <- current_device_id(Map.get(attrs, :device_id)),
         {:ok, state_head_hash} <- pinned_head(Map.get(attrs, :state_head_hash)),
         {:ok, consent_head_hash} <- pinned_head(Map.get(attrs, :consent_head_hash)),
         {:ok, bundle} <- current_storage_bundle(application.id, state_head_hash),
         {:ok, consent} <-
           current_storage_consent(
             application.id,
             Map.get(attrs, :user_id),
             device_id,
             consent_head_hash
           ),
         {:ok, activation} <-
           current_storage_activation(
             application,
             consent,
             Map.get(attrs, :user_id),
             device_id
           ),
         :ok <- consent_matches_bundle(consent, bundle),
         {:ok, freshness} <-
           runtime_freshness(attrs, application, bundle, activation, consent, device_id),
         :ok <-
           storage_permission_granted(
             bundle,
             Map.get(attrs, :surface),
             Map.get(attrs, :operation)
           ),
         :ok <- storage_document_scope_granted(bundle, attrs) do
      {:ok,
       %{
         application: application,
         activation: activation,
         bundle: bundle,
         consent: consent,
         state_head_hash: state_head_hash,
         consent_head_hash: consent_head_hash,
         capability_grant_id: freshness.capability_grant_id,
         consent_epoch: freshness.consent_epoch,
         frame_generation: freshness.frame_generation
       }}
    else
      {:error, status, reason} -> {:error, status, reason}
    end
  end

  @spec record_mutation_audit(map()) :: :ok | {:error, :forbidden, String.t()}
  def record_mutation_audit(attrs) when is_map(attrs) do
    storage = Map.fetch!(attrs, :storage)
    application = Map.fetch!(attrs, :application)
    bundle = Map.fetch!(attrs, :bundle)
    consent = Map.fetch!(attrs, :consent)
    operation = Map.fetch!(attrs, :operation)
    storage_bytes = Map.fetch!(attrs, :storage_bytes)
    resource_key = Map.get(storage, :key) || "record"
    user_id = Map.fetch!(attrs, :user_id)
    device_id = Map.get(attrs, :device_id)
    activation = Map.fetch!(attrs, :activation)
    application = Repo.preload(application, :package)

    audit_attrs = %{
      "type" => "plugin.storage.written",
      "workspace_id" => storage.workspace_id,
      "plugin_id" => application.plugin_id,
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => application.package.owner_scope_kind,
      "capability_grant_id" => Map.fetch!(attrs, :capability_grant_id),
      "consent_epoch" => Map.fetch!(attrs, :consent_epoch),
      "frame_generation" => Map.fetch!(attrs, :frame_generation),
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "operation" => "storage.#{storage.surface}.#{operation}",
      "action" => %{
        "operation" => "storage.#{storage.surface}.#{operation}",
        "result" => "allowed",
        "reason_code" => nil
      },
      "resource" => %{
        "kind" => "plugin",
        "id" => "#{application.plugin_id}:#{resource_key}",
        "version_hash" => bundle.bundle_hash
      },
      "sensitivity" => %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 0,
        "storage_bytes" => storage_bytes
      },
      "correlation" => %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => Map.fetch!(attrs, :consent_head_hash)
      }
    }

    with true <-
           audit_attrs["capability_grant_id"] ==
             RuntimeDescriptors.capability_grant_id(
               application,
               bundle,
               activation,
               consent,
               user_id,
               device_id
             ),
         :ok <- RuntimeAudit.validate_event(audit_attrs, user_id, device_id),
         {:ok, _audit} <-
           Security.record_plugin_runtime_event(
             audit_attrs,
             user_id,
             device_id
           ) do
      :ok
    else
      _ -> {:error, :forbidden, "plugin_storage_audit_required"}
    end
  end

  defp parse_positive_integer(value) when is_integer(value) and value > 0, do: value

  defp parse_positive_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} when integer > 0 -> integer
      _ -> nil
    end
  end

  defp parse_positive_integer(_value), do: nil

  @spec put_kv(map()) :: {:ok, PluginKV.t()} | {:error, Ecto.Changeset.t()}
  def put_kv(attrs) when is_map(attrs), do: upsert_storage_entry(PluginKV, attrs)

  @spec put_record(map()) :: {:ok, PluginRecord.t()} | {:error, Ecto.Changeset.t()}
  def put_record(attrs) when is_map(attrs) do
    attrs = normalize_storage_attrs(attrs)

    with {:ok, application} <- fetch_storage_application(attrs),
         :ok <- validate_storage_application(attrs, application) do
      %PluginRecord{}
      |> PluginRecord.changeset(attrs)
      |> Repo.insert()
    end
  end

  @spec get_kv(Ecto.UUID.t(), storage_scope(), String.t(), String.t()) ::
          PluginKV.t() | nil
  def get_kv(application_id, scope, scope_id, key) do
    get_storage_entry(PluginKV, application_id, scope, scope_id, key)
  end

  @spec get_record(Ecto.UUID.t(), Ecto.UUID.t(), storage_scope(), String.t()) ::
          PluginRecord.t() | nil
  def get_record(record_id, application_id, scope, scope_id) do
    get_record_entry(record_id, application_id, scope, scope_id)
  end

  @spec delete_kv(Ecto.UUID.t(), storage_scope(), String.t(), String.t()) ::
          {:ok, PluginKV.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def delete_kv(application_id, scope, scope_id, key) do
    delete_storage_entry(PluginKV, application_id, scope, scope_id, key)
  end

  @spec delete_record(Ecto.UUID.t(), Ecto.UUID.t(), storage_scope(), String.t()) ::
          {:ok, PluginRecord.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def delete_record(record_id, application_id, scope, scope_id) do
    case get_record_entry(record_id, application_id, scope, scope_id) do
      nil -> {:error, :not_found}
      record -> Repo.delete(record)
    end
  end

  @spec delete_application_storage(Ecto.UUID.t()) :: :ok
  def delete_application_storage(application_id) do
    Repo.delete_all(from(e in PluginKV, where: e.application_id == ^application_id))
    Repo.delete_all(from(r in PluginRecord, where: r.application_id == ^application_id))
    :ok
  end

  @spec aad(map()) :: map()
  def aad(attrs) when is_map(attrs) do
    %{
      "protocol" => "refmd",
      "version" => 1,
      "purpose" => "plugin_data",
      "plugin_id" => Map.fetch!(attrs, :plugin_id),
      "package_id" => Map.fetch!(attrs, :package_id),
      "application_id" => Map.fetch!(attrs, :application_id),
      "activation_id" => Map.fetch!(attrs, :activation_id),
      "workspace_id" => Map.fetch!(attrs, :workspace_id),
      "scope" => normalize_scope(Map.fetch!(attrs, :scope)),
      "scope_id" => Map.fetch!(attrs, :scope_id),
      "key" => Map.fetch!(attrs, :key)
    }
  end

  defp upsert_storage_entry(schema, attrs) do
    attrs = normalize_storage_attrs(attrs)

    with {:ok, application} <- fetch_storage_application(attrs),
         :ok <- validate_storage_application(attrs, application) do
      changeset = schema.changeset(struct(schema), attrs)

      if changeset.valid? do
        Repo.insert(
          changeset,
          on_conflict:
            {:replace, [:activation_id, :ciphertext, :nonce, :key_version, :updated_at]},
          conflict_target: [:application_id, :scope, :scope_id, :key]
        )
      else
        {:error, changeset}
      end
    end
  end

  defp get_storage_entry(schema, application_id, scope, scope_id, key) do
    Repo.one(
      from(e in schema,
        where:
          e.application_id == ^application_id and e.scope == ^normalize_scope(scope) and
            e.scope_id == ^scope_id and e.key == ^key,
        limit: 1
      )
    )
  end

  defp delete_storage_entry(schema, application_id, scope, scope_id, key) do
    case get_storage_entry(schema, application_id, scope, scope_id, key) do
      nil -> {:error, :not_found}
      entry -> Repo.delete(entry)
    end
  end

  defp get_record_entry(record_id, application_id, scope, scope_id) do
    Repo.one(
      from(r in PluginRecord,
        where:
          r.id == ^record_id and r.application_id == ^application_id and
            r.scope == ^normalize_scope(scope) and r.scope_id == ^scope_id,
        limit: 1
      )
    )
  end

  defp normalize_storage_attrs(attrs) do
    Map.update(attrs, :scope, nil, &normalize_scope/1)
  end

  defp normalize_scope(scope) when is_atom(scope), do: Atom.to_string(scope)
  defp normalize_scope(scope), do: scope

  defp fetch_authorization_application(attrs) do
    case fetch_application(Map.get(attrs, :application_id)) do
      {:ok, %PluginApplication{enabled: true} = application} ->
        case Applications.validate_runtime_policy(application) do
          :ok ->
            validate_authorization_application(attrs, application)

          {:error, :plugin_workspace_policy_denied} ->
            {:error, :forbidden, "plugin_workspace_policy_denied"}
        end

      {:ok, %PluginApplication{enabled: false}} ->
        {:error, :forbidden, "plugin_application_disabled"}

      {:ok, %PluginApplication{}} ->
        {:error, :not_found, "not_found"}

      {:error, :application_not_found} ->
        {:error, :not_found, "not_found"}
    end
  end

  defp validate_authorization_application(attrs, application) do
    if application.workspace_id == Map.get(attrs, :workspace_id) do
      validate_authorization_plugin(attrs, application)
    else
      {:error, :not_found, "not_found"}
    end
  end

  defp validate_authorization_plugin(attrs, application) do
    if Map.get(attrs, :plugin_id) in [nil, application.plugin_id] do
      {:ok, application}
    else
      {:error, :forbidden, "application_mismatch"}
    end
  end

  defp validate_authorization_document_scope(%{surface: "workspace"}), do: :ok

  defp validate_authorization_document_scope(%{
         surface: "document",
         workspace_id: workspace_id,
         scope_id: document_id
       }) do
    case Documents.get_document(document_id) do
      %{workspace_id: ^workspace_id} -> :ok
      %{workspace_id: _} -> {:error, :forbidden, "document_scope_denied"}
      nil -> {:error, :not_found, "document_not_found"}
    end
  end

  defp validate_authorization_document_scope(_attrs),
    do: {:error, :forbidden, "document_scope_denied"}

  defp current_device_id(device_id) when is_binary(device_id), do: {:ok, device_id}
  defp current_device_id(_device_id), do: {:error, :forbidden, "plugin_storage_context_required"}

  defp pinned_head(value) when is_binary(value) do
    if String.trim(value) == "" do
      {:error, :forbidden, "plugin_storage_context_required"}
    else
      {:ok, value}
    end
  end

  defp pinned_head(_value), do: {:error, :forbidden, "plugin_storage_context_required"}

  defp current_storage_bundle(application_id, state_head_hash) do
    case Bundles.current_with_pin(application_id, state_head_hash) do
      {:ok, bundle} -> {:ok, Repo.preload(bundle, :candidate)}
      {:error, _reason} -> {:error, :forbidden, "plugin_storage_state_invalid"}
    end
  end

  defp current_storage_consent(application_id, user_id, device_id, consent_head_hash) do
    case Consent.allowed_with_pin(application_id, user_id, device_id, consent_head_hash) do
      {:ok, consent} -> {:ok, consent}
      {:error, _reason} -> {:error, :forbidden, "plugin_storage_consent_invalid"}
    end
  end

  defp current_storage_activation(application, consent, user_id, device_id) do
    case Repo.get(PluginActivation, consent.activation_id) do
      %PluginActivation{
        enabled: true,
        deleted_at: nil,
        application_id: application_id,
        user_id: activation_user_id,
        device_id: activation_device_id
      } = activation
      when application_id == application.id and activation_user_id == user_id and
             (activation_device_id == device_id or is_nil(activation_device_id)) ->
        {:ok, activation}

      %PluginActivation{} ->
        {:error, :forbidden, "plugin_storage_context_invalid"}

      nil ->
        {:error, :forbidden, "plugin_storage_context_invalid"}
    end
  end

  defp runtime_freshness(attrs, application, bundle, activation, consent, device_id) do
    with {:ok, consent_epoch} <- positive_integer_attr(attrs, :consent_epoch),
         true <- consent_epoch == consent.consent_epoch,
         {:ok, frame_generation} <- positive_integer_attr(attrs, :frame_generation),
         {:ok, capability_grant_id} <- non_empty_attr(attrs, :capability_grant_id),
         true <-
           capability_grant_id ==
             RuntimeDescriptors.capability_grant_id(
               application,
               bundle,
               activation,
               consent,
               consent.user_id,
               device_id
             ),
         true <-
           SandboxDocuments.current_frame?(%{
             workspace_id: application.workspace_id,
             package_id: application.package_id,
             application_id: application.id,
             activation_id: activation.id,
             owner_scope_kind: consent.owner_scope_kind,
             user_id: consent.user_id,
             device_id: device_id,
             state_head_hash: application.state_head_hash,
             consent_head_hash: consent.event_hash,
             consent_epoch: consent_epoch,
             capability_grant_id: capability_grant_id,
             frame_generation: frame_generation
           }) do
      {:ok,
       %{
         capability_grant_id: capability_grant_id,
         consent_epoch: consent_epoch,
         frame_generation: frame_generation
       }}
    else
      _ -> {:error, :forbidden, "plugin_storage_context_invalid"}
    end
  end

  defp positive_integer_attr(attrs, key) do
    case parse_positive_integer(Map.get(attrs, key)) do
      integer when is_integer(integer) -> {:ok, integer}
      nil -> {:error, :forbidden, "plugin_storage_context_invalid"}
    end
  end

  defp non_empty_attr(attrs, key) do
    case Map.get(attrs, key) do
      value when is_binary(value) ->
        if String.trim(value) == "" do
          {:error, :forbidden, "plugin_storage_context_invalid"}
        else
          {:ok, value}
        end

      _ ->
        {:error, :forbidden, "plugin_storage_context_invalid"}
    end
  end

  defp consent_matches_bundle(%PluginConsentEvent{} = consent, %PluginBundle{} = bundle) do
    if Consent.matches_bundle?(bundle, consent) do
      :ok
    else
      {:error, :forbidden, "plugin_storage_consent_invalid"}
    end
  end

  defp storage_permission_granted(bundle, surface, operation) do
    permission = "storage:#{operation}:#{surface}"

    bundle
    |> runtime_manifest_permissions()
    |> Enum.member?(permission)
    |> case do
      true -> :ok
      false -> {:error, :forbidden, "plugin_storage_permission_denied"}
    end
  end

  defp runtime_manifest_permissions(%{
         candidate: %{manifest_json: %{"permissions" => permissions}}
       })
       when is_list(permissions) do
    Enum.filter(permissions, &is_binary/1)
  end

  defp runtime_manifest_permissions(_bundle), do: []

  defp storage_document_scope_granted(_bundle, %{surface: "workspace"}), do: :ok

  defp storage_document_scope_granted(bundle, %{surface: "document", scope_id: document_id}) do
    if manifest_document_scope_allows?(bundle.manifest_json, document_id) do
      :ok
    else
      {:error, :forbidden, "document_scope_denied"}
    end
  end

  defp storage_document_scope_granted(_bundle, _attrs),
    do: {:error, :forbidden, "document_scope_denied"}

  defp manifest_document_scope_allows?(%{"documentScopes" => scopes}, document_id)
       when is_list(scopes) and is_binary(document_id) do
    Enum.any?(scopes, &document_scope_allows?(&1, document_id))
  end

  defp manifest_document_scope_allows?(_manifest, _document_id), do: false

  defp document_scope_allows?(%{"kind" => "workspace"}, _document_id), do: true

  defp document_scope_allows?(%{"kind" => kind} = scope, document_id)
       when kind in ["allowed_documents", "allowedDocuments", "allowed_document", "document"] do
    document_id in document_scope_ids(scope)
  end

  defp document_scope_allows?(%{"kind" => kind} = scope, document_id)
       when kind in ["active_document", "activeDocument", "active"] do
    document_id == document_scope_id(scope)
  end

  defp document_scope_allows?(%{"kind" => kind} = scope, document_id)
       when kind in ["selected_documents", "selectedDocuments", "selected"] do
    document_id in document_scope_ids(scope)
  end

  defp document_scope_allows?(_scope, _document_id), do: false

  defp document_scope_id(scope) do
    Enum.find_value(["documentId", "document_id", "id"], fn key ->
      case Map.get(scope, key) do
        value when is_binary(value) and value != "" -> value
        _ -> nil
      end
    end)
  end

  defp document_scope_ids(scope) do
    scope
    |> document_scope_ids_value()
    |> List.wrap()
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
  end

  defp document_scope_ids_value(scope) do
    Enum.find_value(
      ["documentIds", "document_ids", "ids", "documentId", "document_id", "id"],
      fn key -> Map.get(scope, key) end
    )
  end

  defp fetch_storage_application(attrs) do
    case Map.get(attrs, :application_id) do
      nil -> {:error, :application_not_found}
      application_id -> fetch_application(application_id)
    end
  end

  defp fetch_application(application_id) do
    case Repo.get(PluginApplication, application_id) do
      nil -> {:error, :application_not_found}
      application -> {:ok, application}
    end
  end

  defp validate_storage_application(attrs, application) do
    workspace_id = Map.get(attrs, :workspace_id)
    plugin_id = Map.get(attrs, :plugin_id)
    package_id = Map.get(attrs, :package_id)

    if workspace_id == application.workspace_id and plugin_id == application.plugin_id and
         package_id == application.package_id do
      :ok
    else
      {:error, :bundle_application_mismatch}
    end
  end
end
