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
    RuntimeAudit,
    RuntimeBundles,
    RuntimeDescriptors,
    SandboxDocuments,
    Storage
  }

  defdelegate create_application(attrs), to: Applications, as: :create

  defdelegate list_user_packages(user_id), to: Packages, as: :list_for_user

  defdelegate get_package(package_id), to: Packages, as: :get

  defdelegate list_workspace_packages(workspace_id), to: Packages, as: :list_for_workspace

  defdelegate create_activation(attrs), to: Activations, as: :create

  defdelegate get_activation(activation_id), to: Activations, as: :get

  defdelegate get_active_activation(activation_id), to: Activations, as: :get_active

  defdelegate update_activation(activation, attrs, opts \\ []), to: Activations, as: :update

  defdelegate delete_activation(activation, opts \\ []), to: Activations, as: :delete

  defdelegate list_activations(user_id, device_id), to: Activations, as: :list_for_actor

  defdelegate apply_package_to_workspace(workspace_id, package_id, user_id, device_id),
    to: Applications,
    as: :apply_package

  defdelegate ensure_personal_package_runtime(workspace_id, package, user_id, device_id),
    to: Applications

  defdelegate ensure_existing_personal_package_runtime(workspace_id, package, user_id, device_id),
    to: Applications

  defdelegate ensure_personal_workspace_applications(workspace_id, user_id, device_id),
    to: Applications

  defdelegate recompute_workspace_user_plugin_policy(workspace_id),
    to: Applications,
    as: :recompute_workspace_user_policy

  defdelegate list_applications(workspace_id), to: Applications, as: :list

  defdelegate get_application(id), to: Applications, as: :get

  defdelegate get_bundle_candidate(id), to: BundleCandidates, as: :get

  defdelegate list_runtime_descriptors(workspace_id, user_id, device_id),
    to: RuntimeDescriptors,
    as: :list

  defdelegate list_consent_required_descriptors(workspace_id, user_id, device_id),
    to: RuntimeDescriptors,
    as: :list_consent_required

  defdelegate validate_runtime_audit_event(attrs), to: RuntimeAudit, as: :validate_event

  defdelegate validate_runtime_audit_event(attrs, user_id, device_id),
    to: RuntimeAudit,
    as: :validate_event

  defdelegate apply_runtime_audit_frame_lifecycle(attrs, user_id, device_id),
    to: RuntimeAudit,
    as: :apply_frame_lifecycle

  defdelegate update_application(application, attrs), to: Applications, as: :update

  defdelegate delete_application(application), to: Applications, as: :delete

  defdelegate create_local_bundle_candidate(path, attrs), to: BundleCandidates, as: :create_local

  def create_scope_authorized_local_bundle_candidate(path, attrs, authorize_candidate)
      when is_function(authorize_candidate, 1) do
    BundleCandidates.create_local(path, attrs, authorize_candidate: authorize_candidate)
  end

  defdelegate create_remote_bundle_candidate(source_url, attrs),
    to: BundleCandidates,
    as: :create_remote

  def create_scope_authorized_remote_bundle_candidate(source_url, attrs, authorize_candidate)
      when is_function(authorize_candidate, 1) do
    BundleCandidates.create_remote(source_url, attrs, authorize_candidate: authorize_candidate)
  end

  defdelegate plugin_bundle_approval_subject(candidate, attrs),
    to: Approvals,
    as: :subject

  defdelegate plugin_bundle_approval_subject_hash(candidate, attrs),
    to: Approvals,
    as: :subject_hash

  defdelegate next_package_approval_chain(package_id), to: Approvals

  defdelegate promote_bundle_candidate(candidate, attrs), to: Approvals, as: :promote

  defdelegate create_bundle(attrs), to: Bundles, as: :create

  defdelegate list_bundles(application_id), to: Bundles, as: :list

  defdelegate pin_current_bundle(application, bundle), to: Bundles, as: :pin_current

  defdelegate pin_current_bundle(application, bundle, opts), to: Bundles, as: :pin_current

  defdelegate current_bundle_with_pin(application_id, trusted_state_head_hash),
    to: Bundles,
    as: :current_with_pin

  defdelegate cleanup_package_storage(opts \\ []), to: PackageEntries, as: :cleanup_storage

  defdelegate authorize_storage_context(attrs), to: Storage, as: :authorize_context

  defdelegate record_storage_mutation_audit(attrs), to: Storage, as: :record_mutation_audit

  defdelegate put_kv(attrs), to: Storage

  defdelegate put_record(attrs), to: Storage

  defdelegate get_kv(application_id, scope, scope_id, key), to: Storage

  defdelegate get_record(record_id, application_id, scope, scope_id), to: Storage

  defdelegate delete_kv(application_id, scope, scope_id, key), to: Storage

  defdelegate delete_record(record_id, application_id, scope, scope_id), to: Storage

  defdelegate storage_aad(attrs), to: Storage, as: :aad

  defdelegate consent_subject(attrs), to: Consent, as: :subject

  defdelegate consent_subject_hash(attrs), to: Consent, as: :subject_hash

  defdelegate append_consent_event(attrs), to: Consent, as: :append_event

  defdelegate latest_consent_event(application_id, user_id, device_id),
    to: Consent,
    as: :latest_event

  defdelegate allowed_consent_with_pin(application_id, user_id, device_id, trusted_head_hash),
    to: Consent,
    as: :allowed_with_pin

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

  defdelegate create_sandbox_document_session(attrs), to: SandboxDocuments, as: :create

  defdelegate consume_sandbox_document_session(session_id, expected),
    to: SandboxDocuments,
    as: :consume

  defdelegate current_sandbox_document_frame?(attrs), to: SandboxDocuments, as: :current_frame?

  defdelegate mark_sandbox_document_served(session), to: SandboxDocuments, as: :mark_served

  defdelegate activate_sandbox_document_frame?(attrs), to: SandboxDocuments, as: :activate_frame?

  defdelegate revoke_sandbox_document_frame(attrs), to: SandboxDocuments, as: :revoke_frame
end
