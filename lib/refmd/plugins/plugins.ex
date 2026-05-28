defmodule RefMD.Plugins do
  @moduledoc """
  The Plugins context. Manages third-party plugin application state, storage, and consent events.
  """

  alias RefMD.Plugins.{
    Activations,
    Applications,
    Approvals,
    BundleCandidates,
    Bundles,
    Consent,
    PackageEntries,
    Packages,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginBundleCandidate,
    PluginConsentEvent,
    PluginKV,
    PluginPackage,
    PluginRecord,
    RuntimeAudit,
    RuntimeBundles,
    RuntimeDescriptors,
    SandboxDocuments,
    Storage
  }

  @type storage_scope :: :document | :workspace | String.t()
  @type plugin_error ::
          :bundle_application_mismatch
          | :application_not_found
          | :plugin_bundle_not_pinned
          | :plugin_consent_head_pin_required
          | :plugin_consent_not_allowed
          | :plugin_consent_rollback
          | :plugin_application_disabled
          | :plugin_activation_disabled
          | :plugin_workspace_policy_denied
          | :plugin_state_head_mismatch
          | :plugin_state_head_pin_required
          | :plugin_state_rollback
          | :plugin_bundle_candidate_invalid
          | :plugin_bundle_approval_forbidden
          | :plugin_bundle_approval_hash_mismatch
          | :plugin_bundle_approval_rollback
          | :plugin_bundle_approval_signature_invalid
          | :plugin_bundle_candidate_missing
          | :plugin_bundle_runtime_hash_mismatch
          | :plugin_application_not_found
          | :plugin_package_forbidden
          | :plugin_package_not_found
          | :plugin_package_scope_unsupported
          | :plugin_workspace_application_required
          | :plugin_manifest_dangerous_permission_combination
          | :stale_consent_head
          | :invalid_consent_genesis
          | :plugin_consent_event_hash_mismatch
          | :plugin_consent_event_signature_invalid

  @spec create_application(map()) ::
          {:ok, PluginApplication.t()} | {:error, Ecto.Changeset.t()}
  defdelegate create_application(attrs), to: Applications, as: :create

  @spec list_user_packages(Ecto.UUID.t()) :: [PluginPackage.t()]
  defdelegate list_user_packages(user_id), to: Packages, as: :list_for_user

  @spec get_package(Ecto.UUID.t()) :: PluginPackage.t() | nil
  defdelegate get_package(package_id), to: Packages, as: :get

  @spec list_workspace_packages(Ecto.UUID.t()) :: [PluginPackage.t()]
  defdelegate list_workspace_packages(workspace_id), to: Packages, as: :list_for_workspace

  @spec create_activation(map()) ::
          {:ok, PluginActivation.t()} | {:error, Ecto.Changeset.t()}
  defdelegate create_activation(attrs), to: Activations, as: :create

  @spec get_activation(Ecto.UUID.t()) :: PluginActivation.t() | nil
  defdelegate get_activation(activation_id), to: Activations, as: :get

  @spec get_active_activation(Ecto.UUID.t()) :: PluginActivation.t() | nil
  defdelegate get_active_activation(activation_id), to: Activations, as: :get_active

  @spec update_activation(PluginActivation.t(), map(), keyword()) ::
          {:ok, PluginActivation.t()} | {:error, Ecto.Changeset.t()}
  defdelegate update_activation(activation, attrs, opts \\ []), to: Activations, as: :update

  @spec delete_activation(PluginActivation.t(), keyword()) ::
          {:ok, PluginActivation.t()} | {:error, Ecto.Changeset.t() | plugin_error() | atom()}
  defdelegate delete_activation(activation, opts \\ []), to: Activations, as: :delete

  @spec list_activations(Ecto.UUID.t(), Ecto.UUID.t() | nil) :: [PluginActivation.t()]
  defdelegate list_activations(user_id, device_id), to: Activations, as: :list_for_actor

  @spec apply_package_to_workspace(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, %{application: PluginApplication.t(), activation: PluginActivation.t()}}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate apply_package_to_workspace(workspace_id, package_id, user_id, device_id),
    to: Applications,
    as: :apply_package

  @spec ensure_personal_package_runtime(
          Ecto.UUID.t(),
          PluginPackage.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, %{application: PluginApplication.t(), activation: PluginActivation.t()}}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate ensure_personal_package_runtime(workspace_id, package, user_id, device_id),
    to: Applications

  @spec ensure_existing_personal_package_runtime(
          Ecto.UUID.t(),
          PluginPackage.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) ::
          {:ok, %{application: PluginApplication.t(), activation: PluginActivation.t()}}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate ensure_existing_personal_package_runtime(workspace_id, package, user_id, device_id),
    to: Applications

  @spec ensure_personal_workspace_applications(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) :: :ok
  defdelegate ensure_personal_workspace_applications(workspace_id, user_id, device_id),
    to: Applications

  @spec recompute_workspace_user_plugin_policy(Ecto.UUID.t()) :: :ok | {:error, term()}
  defdelegate recompute_workspace_user_plugin_policy(workspace_id),
    to: Applications,
    as: :recompute_workspace_user_policy

  @spec list_applications(Ecto.UUID.t()) :: [PluginApplication.t()]
  defdelegate list_applications(workspace_id), to: Applications, as: :list

  @spec get_application(Ecto.UUID.t()) :: PluginApplication.t() | nil
  defdelegate get_application(id), to: Applications, as: :get

  @spec get_bundle_candidate(Ecto.UUID.t()) :: PluginBundleCandidate.t() | nil
  defdelegate get_bundle_candidate(id), to: BundleCandidates, as: :get

  @spec list_runtime_descriptors(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: [map()]
  defdelegate list_runtime_descriptors(workspace_id, user_id, device_id),
    to: RuntimeDescriptors,
    as: :list

  @spec list_consent_required_descriptors(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: [map()]
  defdelegate list_consent_required_descriptors(workspace_id, user_id, device_id),
    to: RuntimeDescriptors,
    as: :list_consent_required

  @spec validate_runtime_audit_event(map()) :: :ok | {:error, atom()}
  defdelegate validate_runtime_audit_event(attrs), to: RuntimeAudit, as: :validate_event

  @spec validate_runtime_audit_event(map(), Ecto.UUID.t(), Ecto.UUID.t() | nil) ::
          :ok | {:error, atom()}
  defdelegate validate_runtime_audit_event(attrs, user_id, device_id),
    to: RuntimeAudit,
    as: :validate_event

  @spec apply_runtime_audit_frame_lifecycle(map(), Ecto.UUID.t(), Ecto.UUID.t() | nil) ::
          :ok | {:error, atom()}
  defdelegate apply_runtime_audit_frame_lifecycle(attrs, user_id, device_id),
    to: RuntimeAudit,
    as: :apply_frame_lifecycle

  @spec update_application(PluginApplication.t(), map()) ::
          {:ok, PluginApplication.t()} | {:error, Ecto.Changeset.t()}
  defdelegate update_application(application, attrs), to: Applications, as: :update

  @spec delete_application(PluginApplication.t()) ::
          {:ok, PluginApplication.t()} | {:error, Ecto.Changeset.t()}
  defdelegate delete_application(application), to: Applications, as: :delete

  @spec create_local_bundle_candidate(Path.t(), map()) ::
          {:ok, PluginBundleCandidate.t()}
          | {:error, Ecto.Changeset.t() | plugin_error() | atom()}
  defdelegate create_local_bundle_candidate(path, attrs), to: BundleCandidates, as: :create_local

  @spec create_scope_authorized_local_bundle_candidate(
          Path.t(),
          map(),
          (map() -> :ok | {:error, atom()})
        ) ::
          {:ok, PluginBundleCandidate.t()}
          | {:error, Ecto.Changeset.t() | plugin_error() | atom()}
  def create_scope_authorized_local_bundle_candidate(path, attrs, authorize_candidate)
      when is_function(authorize_candidate, 1) do
    BundleCandidates.create_local(path, attrs, authorize_candidate: authorize_candidate)
  end

  @spec create_remote_bundle_candidate(String.t(), map()) ::
          {:ok, PluginBundleCandidate.t()}
          | {:error, Ecto.Changeset.t() | plugin_error() | atom()}
  defdelegate create_remote_bundle_candidate(source_url, attrs),
    to: BundleCandidates,
    as: :create_remote

  @spec create_scope_authorized_remote_bundle_candidate(
          String.t(),
          map(),
          (map() -> :ok | {:error, atom()})
        ) ::
          {:ok, PluginBundleCandidate.t()}
          | {:error, Ecto.Changeset.t() | plugin_error() | atom()}
  def create_scope_authorized_remote_bundle_candidate(source_url, attrs, authorize_candidate)
      when is_function(authorize_candidate, 1) do
    BundleCandidates.create_remote(source_url, attrs, authorize_candidate: authorize_candidate)
  end

  @spec plugin_bundle_approval_subject(map() | PluginBundleCandidate.t(), map()) :: map()
  defdelegate plugin_bundle_approval_subject(candidate, attrs),
    to: Approvals,
    as: :subject

  @spec plugin_bundle_approval_subject_hash(map() | PluginBundleCandidate.t(), map()) ::
          String.t()
  defdelegate plugin_bundle_approval_subject_hash(candidate, attrs),
    to: Approvals,
    as: :subject_hash

  @spec next_package_approval_chain(Ecto.UUID.t()) :: {pos_integer(), String.t()}
  defdelegate next_package_approval_chain(package_id), to: Approvals

  @spec promote_bundle_candidate(PluginBundleCandidate.t(), map()) ::
          {:ok, PluginPackage.t()}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate promote_bundle_candidate(candidate, attrs), to: Approvals, as: :promote

  @spec create_bundle(map()) ::
          {:ok, PluginBundle.t()} | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate create_bundle(attrs), to: Bundles, as: :create

  @spec list_bundles(Ecto.UUID.t()) :: [PluginBundle.t()]
  defdelegate list_bundles(application_id), to: Bundles, as: :list

  @spec pin_current_bundle(PluginApplication.t(), PluginBundle.t()) ::
          {:ok, PluginApplication.t()}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate pin_current_bundle(application, bundle), to: Bundles, as: :pin_current

  @spec pin_current_bundle(PluginApplication.t(), PluginBundle.t(), keyword()) ::
          {:ok, PluginApplication.t()}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate pin_current_bundle(application, bundle, opts), to: Bundles, as: :pin_current

  @spec current_bundle_with_pin(Ecto.UUID.t(), String.t() | nil) ::
          {:ok, PluginBundle.t()} | {:error, plugin_error()}
  defdelegate current_bundle_with_pin(application_id, trusted_state_head_hash),
    to: Bundles,
    as: :current_with_pin

  @spec cleanup_package_storage(keyword()) :: {:ok, map()} | {:error, atom()}
  defdelegate cleanup_package_storage(opts \\ []), to: PackageEntries, as: :cleanup_storage

  @spec authorize_storage_context(map()) :: {:ok, map()} | {:error, atom(), String.t()}
  defdelegate authorize_storage_context(attrs), to: Storage, as: :authorize_context

  @spec record_storage_mutation_audit(map()) :: :ok | {:error, :forbidden, String.t()}
  defdelegate record_storage_mutation_audit(attrs), to: Storage, as: :record_mutation_audit

  @spec put_kv(map()) :: {:ok, PluginKV.t()} | {:error, Ecto.Changeset.t()}
  defdelegate put_kv(attrs), to: Storage

  @spec put_record(map()) :: {:ok, PluginRecord.t()} | {:error, Ecto.Changeset.t()}
  defdelegate put_record(attrs), to: Storage

  @spec get_kv(Ecto.UUID.t(), storage_scope(), String.t(), String.t()) ::
          PluginKV.t() | nil
  defdelegate get_kv(application_id, scope, scope_id, key), to: Storage

  @spec get_record(Ecto.UUID.t(), Ecto.UUID.t(), storage_scope(), String.t()) ::
          PluginRecord.t() | nil
  defdelegate get_record(record_id, application_id, scope, scope_id), to: Storage

  @spec delete_kv(Ecto.UUID.t(), storage_scope(), String.t(), String.t()) ::
          {:ok, PluginKV.t()} | {:error, :not_found | Ecto.Changeset.t()}
  defdelegate delete_kv(application_id, scope, scope_id, key), to: Storage

  @spec delete_record(Ecto.UUID.t(), Ecto.UUID.t(), storage_scope(), String.t()) ::
          {:ok, PluginRecord.t()} | {:error, :not_found | Ecto.Changeset.t()}
  defdelegate delete_record(record_id, application_id, scope, scope_id), to: Storage

  @spec storage_aad(map()) :: map()
  defdelegate storage_aad(attrs), to: Storage, as: :aad

  @spec consent_subject(map() | PluginConsentEvent.t()) :: map()
  defdelegate consent_subject(attrs), to: Consent, as: :subject

  @spec consent_subject_hash(map() | PluginConsentEvent.t()) :: String.t()
  defdelegate consent_subject_hash(attrs), to: Consent, as: :subject_hash

  @spec append_consent_event(map()) ::
          {:ok, PluginConsentEvent.t()}
          | {:error, Ecto.Changeset.t() | plugin_error()}
  defdelegate append_consent_event(attrs), to: Consent, as: :append_event

  @spec latest_consent_event(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          PluginConsentEvent.t() | nil
  defdelegate latest_consent_event(application_id, user_id, device_id),
    to: Consent,
    as: :latest_event

  @spec allowed_consent_with_pin(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), String.t() | nil) ::
          {:ok, PluginConsentEvent.t()}
          | {:error,
             :not_found
             | :plugin_consent_head_pin_required
             | :plugin_consent_rollback
             | :plugin_consent_not_allowed
             | :plugin_activation_disabled}
  defdelegate allowed_consent_with_pin(application_id, user_id, device_id, trusted_head_hash),
    to: Consent,
    as: :allowed_with_pin

  @spec runtime_bundle_with_pins(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t() | nil,
          String.t() | nil
        ) ::
          {:ok, map()}
          | {:error,
             plugin_error()
             | :not_found
             | :plugin_bundle_candidate_missing
             | :plugin_bundle_runtime_hash_mismatch}
  defdelegate runtime_bundle_with_pins(
                runtime_target_id,
                workspace_id,
                user_id,
                device_id,
                trusted_state_head_hash,
                trusted_consent_head_hash
              ),
              to: RuntimeBundles,
              as: :with_pins

  @spec create_sandbox_document_session(map()) :: SandboxDocuments.session()
  defdelegate create_sandbox_document_session(attrs), to: SandboxDocuments, as: :create

  @spec consume_sandbox_document_session(String.t(), map()) ::
          {:ok, SandboxDocuments.session()} | {:error, atom()}
  defdelegate consume_sandbox_document_session(session_id, expected),
    to: SandboxDocuments,
    as: :consume

  @spec current_sandbox_document_frame?(map()) :: boolean()
  defdelegate current_sandbox_document_frame?(attrs), to: SandboxDocuments, as: :current_frame?

  @spec mark_sandbox_document_served(SandboxDocuments.session()) :: :ok
  defdelegate mark_sandbox_document_served(session), to: SandboxDocuments, as: :mark_served

  @spec activate_sandbox_document_frame?(map()) :: boolean()
  defdelegate activate_sandbox_document_frame?(attrs), to: SandboxDocuments, as: :activate_frame?

  @spec revoke_sandbox_document_frame(map()) :: :ok
  defdelegate revoke_sandbox_document_frame(attrs), to: SandboxDocuments, as: :revoke_frame
end
