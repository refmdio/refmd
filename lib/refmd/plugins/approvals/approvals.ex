defmodule RefMD.Plugins.Approvals do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Crypto.Signature.Plugin, as: PluginSignature
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.Authority, as: KeyDirectoryAuthority

  alias RefMD.Plugins.{
    Applications,
    Artifact,
    PackageEntries,
    Packages,
    PluginApplication,
    PluginBundle,
    PluginBundleCandidate,
    PluginPackage,
    Signing
  }

  alias RefMD.Repo
  alias RefMD.Security

  @genesis_event_hash "GENESIS"

  def subject(%PluginBundleCandidate{} = candidate, attrs),
    do: subject(Map.from_struct(candidate), attrs)

  def subject(candidate, attrs) when is_map(candidate) and is_map(attrs) do
    Artifact.approval_subject(candidate, attrs)
  end

  def subject_hash(candidate, attrs) do
    candidate
    |> subject(attrs)
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  def next_package_approval_chain(package_id) when is_binary(package_id) do
    case Packages.get(package_id) do
      %PluginPackage{state_head_hash: state_head_hash} = package
      when is_binary(state_head_hash) ->
        latest =
          from(b in PluginBundle,
            where: b.package_id == ^package.id and is_nil(b.application_id),
            order_by: [desc: b.approval_epoch],
            limit: 1
          )
          |> Repo.one()

        next_epoch =
          case latest do
            %PluginBundle{approval_epoch: approval_epoch} when is_integer(approval_epoch) ->
              approval_epoch + 1

            _ ->
              1
          end

        {next_epoch, state_head_hash}

      _ ->
        {1, @genesis_event_hash}
    end
  end

  def next_package_approval_chain(_package_id), do: {1, @genesis_event_hash}

  def promote(%PluginBundleCandidate{} = candidate, attrs) when is_map(attrs) do
    result =
      with :ok <- validate_candidate_can_promote(candidate),
           {:ok, authority} <- approval_authority(candidate, attrs),
           :ok <- validate_event_hash(candidate, attrs),
           :ok <- validate_signature(candidate, attrs) do
        Repo.transaction(fn -> promote_target(candidate, attrs, authority) end)
      end

    case result do
      {:ok, _subject} = ok -> ok
      {:error, reason} -> record_rejected(candidate, attrs, reason)
    end
  end

  def proof(%PluginBundle{} = bundle) do
    with %PluginBundleCandidate{} = candidate <- Repo.preload(bundle, :candidate).candidate,
         true <- acquisition_hashes_match?(candidate, bundle) do
      proof(bundle, candidate)
    else
      nil -> {:error, :plugin_bundle_candidate_missing}
      false -> {:error, :plugin_bundle_runtime_hash_mismatch}
    end
  end

  defp proof(%PluginBundle{} = bundle, %PluginBundleCandidate{} = candidate) do
    subject_source = subject_source(bundle, candidate)

    approval_attrs = %{
      approver_user_id: bundle.approved_by_user_id,
      approver_device_id: bundle.approved_by_device_id,
      approval_epoch: bundle.approval_epoch,
      previous_approval_event_hash: bundle.previous_approval_event_hash,
      created_at_ms: bundle.approved_at_ms
    }

    with {:ok, device} <-
           Signing.fetch_device(bundle.approved_by_user_id, bundle.approved_by_device_id),
         {:ok, authority} <- stored_authority(bundle, candidate, approval_attrs) do
      approval_subject = subject(subject_source, approval_attrs)

      {:ok,
       %{
         event_hash: bundle.approval_event_hash,
         subject: approval_subject,
         actor: approval_actor(device, candidate),
         hybrid_signature: bundle.hybrid_signature,
         signing_key_id: device.signing_key_id,
         approval_authority: authority
       }}
    else
      _ -> {:error, :plugin_bundle_approval_signature_invalid}
    end
  end

  defp promote_target(candidate, attrs, authority) do
    promote_package_only(candidate, attrs, authority)
  end

  defp promote_package_only(candidate, attrs, authority) do
    case package_for_promotion(candidate, attrs) do
      {:ok, package} -> promote_package_tx(candidate, package, attrs, authority)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp package_for_promotion(%PluginBundleCandidate{} = candidate, attrs) do
    case Packages.get(candidate.package_id) do
      %PluginPackage{} = package ->
        {:ok, package}

      nil ->
        Packages.create(%{
          id: candidate.package_id,
          plugin_id: candidate.plugin_id,
          version: candidate.version,
          owner_scope_kind: candidate.owner_scope_kind,
          owner_workspace_id: candidate.owner_workspace_id,
          owner_user_id: candidate.owner_user_id,
          bundle_hash: candidate.bundle_hash,
          resource_manifest_hash: candidate.resource_manifest_hash,
          created_by_user_id: Map.get(attrs, :approver_user_id),
          created_by_device_id: Map.get(attrs, :approver_device_id),
          state_head_hash: @genesis_event_hash
        })
    end
  end

  defp validate_candidate_can_promote(%PluginBundleCandidate{validation_status: "valid"}),
    do: :ok

  defp validate_candidate_can_promote(%PluginBundleCandidate{}),
    do: {:error, :plugin_bundle_candidate_invalid}

  defp validate_event_hash(candidate, attrs) do
    if Map.get(attrs, :approval_event_hash) == subject_hash(candidate, attrs) do
      :ok
    else
      {:error, :plugin_bundle_approval_hash_mismatch}
    end
  end

  defp validate_signature(candidate, attrs) do
    approver_user_id = Map.get(attrs, :approver_user_id)
    approver_device_id = Map.get(attrs, :approver_device_id)
    approval_subject = subject(candidate, attrs)

    with {:ok, device} <- Signing.fetch_active_device(approver_user_id, approver_device_id),
         actor = approval_actor(device, candidate),
         transcript <-
           PluginSignature.build_plugin_bundle_approval_transcript!(%{
             actor: actor,
             approval: approval_subject
           }),
         :ok <-
           Signing.verify(
             "plugin_bundle_approval",
             transcript,
             Map.get(attrs, :hybrid_signature),
             device,
             %{actor: actor, approval_subject: approval_subject}
           ) do
      :ok
    else
      _ -> {:error, :plugin_bundle_approval_signature_invalid}
    end
  rescue
    ArgumentError -> {:error, :plugin_bundle_approval_signature_invalid}
  end

  defp stored_authority(bundle, candidate, attrs) do
    with :ok <- stored_identity_matches(bundle, candidate, attrs),
         {:ok, authority} <- stored_authority(bundle, candidate) do
      {:ok,
       authority
       |> Map.put("device_id", bundle.approved_by_device_id)
       |> Map.put("signing_key_id", Signing.signing_key_id(bundle.approved_by_device_id))}
    else
      _ -> {:error, :plugin_bundle_approval_forbidden}
    end
  end

  defp stored_identity_matches(bundle, candidate, attrs) do
    checks = [
      bundle.workspace_id == candidate.workspace_id,
      bundle.application_id == candidate.application_id,
      bundle.package_id == candidate.package_id,
      bundle.plugin_id == candidate.plugin_id,
      bundle.approved_by_user_id == Map.get(attrs, :approver_user_id),
      bundle.approved_by_device_id == Map.get(attrs, :approver_device_id)
    ]

    if Enum.all?(checks), do: :ok, else: {:error, :plugin_bundle_approval_forbidden}
  end

  defp stored_authority(bundle, %PluginBundleCandidate{owner_scope_kind: "workspace"} = candidate) do
    with checkpoint when not is_nil(checkpoint) <-
           KeyDirectory.checkpoint_covering_event_head(
             "workspace",
             candidate.owner_workspace_id,
             bundle.approval_authority_event_head_sequence
           ),
         true <- checkpoint.sequence == bundle.approval_authority_checkpoint_sequence,
         true <- checkpoint.checkpoint_hash == bundle.approval_authority_checkpoint_hash,
         true <- checkpoint.covered_event_head_hash == bundle.approval_authority_event_head_hash do
      {:ok,
       %{
         "kind" => "key_directory_membership",
         "scope_kind" => "workspace",
         "workspace_id" => candidate.owner_workspace_id,
         "user_id" => bundle.approved_by_user_id,
         "event_head_sequence" => bundle.approval_authority_event_head_sequence,
         "event_head_hash" => bundle.approval_authority_event_head_hash,
         "checkpoint_sequence" => bundle.approval_authority_checkpoint_sequence,
         "checkpoint_hash" => bundle.approval_authority_checkpoint_hash
       }}
    else
      _ -> {:error, :plugin_bundle_approval_forbidden}
    end
  end

  defp stored_authority(bundle, %PluginBundleCandidate{owner_scope_kind: "user"} = candidate) do
    with checkpoint when not is_nil(checkpoint) <-
           KeyDirectory.checkpoint_covering_event_head(
             "user",
             candidate.owner_user_id,
             bundle.approval_authority_event_head_sequence
           ),
         true <- checkpoint.sequence == bundle.approval_authority_checkpoint_sequence,
         true <- checkpoint.checkpoint_hash == bundle.approval_authority_checkpoint_hash,
         true <- checkpoint.covered_event_head_hash == bundle.approval_authority_event_head_hash do
      {:ok,
       %{
         "kind" => "key_directory_membership",
         "scope_kind" => "user",
         "owner_user_id" => candidate.owner_user_id,
         "user_id" => bundle.approved_by_user_id,
         "event_head_sequence" => bundle.approval_authority_event_head_sequence,
         "event_head_hash" => bundle.approval_authority_event_head_hash,
         "checkpoint_sequence" => bundle.approval_authority_checkpoint_sequence,
         "checkpoint_hash" => bundle.approval_authority_checkpoint_hash
       }}
    else
      _ -> {:error, :plugin_bundle_approval_forbidden}
    end
  end

  defp approval_authority(candidate, attrs) do
    approver_user_id = Map.get(attrs, :approver_user_id)

    with {:ok, checkpoint} <- current_approval_checkpoint(candidate),
         :ok <-
           assert_approval_authority(
             candidate,
             checkpoint.covered_event_head_sequence,
             approver_user_id
           ) do
      {:ok,
       %{
         "kind" => "key_directory_membership",
         "scope_kind" => candidate.owner_scope_kind,
         "workspace_id" => candidate.owner_workspace_id,
         "owner_user_id" => candidate.owner_user_id,
         "user_id" => approver_user_id,
         "event_head_sequence" => checkpoint.covered_event_head_sequence,
         "event_head_hash" => checkpoint.covered_event_head_hash,
         "checkpoint_sequence" => checkpoint.sequence,
         "checkpoint_hash" => checkpoint.checkpoint_hash
       }
       |> reject_nil_values()}
    end
  end

  defp current_approval_checkpoint(
         %PluginBundleCandidate{owner_scope_kind: "workspace"} = candidate
       ) do
    case Encryption.current_workspace_key_directory_checkpoint(candidate.owner_workspace_id) do
      nil -> {:error, :plugin_bundle_approval_forbidden}
      checkpoint -> {:ok, checkpoint}
    end
  end

  defp current_approval_checkpoint(%PluginBundleCandidate{owner_scope_kind: "user"} = candidate) do
    case Encryption.current_user_key_directory_checkpoint(candidate.owner_user_id) do
      nil -> {:error, :plugin_bundle_approval_forbidden}
      checkpoint -> {:ok, checkpoint}
    end
  end

  defp assert_approval_authority(
         %PluginBundleCandidate{owner_scope_kind: "workspace"} = candidate,
         event_head_sequence,
         approver_user_id
       ) do
    assert_workspace_authority(
      candidate.owner_workspace_id,
      event_head_sequence,
      approver_user_id
    )
  end

  defp assert_approval_authority(
         %PluginBundleCandidate{owner_scope_kind: "user", owner_user_id: user_id},
         _event_head_sequence,
         approver_user_id
       ) do
    if user_id == approver_user_id, do: :ok, else: {:error, :plugin_bundle_approval_forbidden}
  end

  defp approval_actor(device, %PluginBundleCandidate{owner_scope_kind: "workspace"} = candidate),
    do: Signing.actor(device, candidate.owner_workspace_id, "workspace")

  defp approval_actor(device, %PluginBundleCandidate{owner_scope_kind: "user"} = candidate),
    do: Signing.actor(device, candidate.owner_user_id, "user")

  defp assert_workspace_authority(workspace_id, event_head_sequence, approver_user_id) do
    KeyDirectoryAuthority.assert_workspace_admin_authority!(
      workspace_id,
      event_head_sequence,
      %{"signer_kind" => "device", "user_id" => approver_user_id}
    )
  rescue
    ArgumentError -> {:error, :plugin_bundle_approval_forbidden}
  end

  defp reject_nil_values(map) do
    Map.reject(map, fn {_key, value} -> is_nil(value) end)
  end

  defp promote_package_tx(candidate, package, attrs, authority) do
    package =
      PluginPackage
      |> where([p], p.id == ^package.id)
      |> lock("FOR UPDATE")
      |> Repo.one!()

    latest =
      from(b in PluginBundle,
        where: b.package_id == ^package.id and is_nil(b.application_id),
        order_by: [desc: b.approval_epoch],
        limit: 1
      )
      |> lock("FOR UPDATE")
      |> Repo.one()

    case validate_package_chain(package, latest, attrs) do
      :ok ->
        insert_and_pin_package_bundle(candidate, package, attrs, authority)

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp validate_package_chain(%PluginPackage{current_bundle_id: nil}, nil, attrs) do
    if Map.get(attrs, :previous_approval_event_hash) == @genesis_event_hash and
         Map.get(attrs, :approval_epoch) == 1 do
      :ok
    else
      {:error, :plugin_bundle_approval_rollback}
    end
  end

  defp validate_package_chain(%PluginPackage{} = package, %PluginBundle{} = latest, attrs) do
    if Map.get(attrs, :previous_approval_event_hash) == package.state_head_hash and
         Map.get(attrs, :approval_epoch) > latest.approval_epoch do
      :ok
    else
      {:error, :plugin_bundle_approval_rollback}
    end
  end

  defp validate_package_chain(_package, _latest, _attrs),
    do: {:error, :plugin_bundle_approval_rollback}

  defp insert_and_pin_package_bundle(candidate, package, attrs, authority) do
    bundle_attrs =
      bundle_attrs(candidate, package, nil, attrs, authority)

    %PluginBundle{}
    |> PluginBundle.changeset(bundle_attrs)
    |> Repo.insert()
    |> case do
      {:ok, bundle} ->
        pin_package_and_audit_or_rollback(candidate, package, bundle)

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp bundle_attrs(candidate, package, application, attrs, authority) do
    %{
      candidate_id: candidate.id,
      package_id: package.id,
      application_id: application && application.id,
      workspace_id: (application && application.workspace_id) || candidate.workspace_id,
      plugin_id: candidate.plugin_id,
      version: candidate.version,
      source_kind: candidate.source_kind,
      source_url_hash: candidate.source_url_hash,
      archive_hash: candidate.archive_hash,
      manifest_json: candidate.manifest_json,
      manifest_json_bytes: candidate.manifest_json_bytes,
      main_js: candidate.main_js,
      styles_css: candidate.styles_css,
      bundle_hash: candidate.bundle_hash,
      manifest_hash: candidate.manifest_hash,
      main_js_hash: candidate.main_js_hash,
      styles_css_hash: candidate.styles_css_hash,
      resource_manifest: candidate.resource_manifest,
      resource_manifest_hash: candidate.resource_manifest_hash,
      permissions_hash: candidate.permissions_hash,
      endpoint_hash: candidate.endpoint_hash,
      renderer_slots_hash: candidate.renderer_slots_hash,
      document_scope_hash: candidate.document_scope_hash,
      approval_epoch: Map.fetch!(attrs, :approval_epoch),
      approval_authority_event_head_sequence: authority["event_head_sequence"],
      approval_authority_event_head_hash: authority["event_head_hash"],
      approval_authority_checkpoint_sequence: authority["checkpoint_sequence"],
      approval_authority_checkpoint_hash: authority["checkpoint_hash"],
      previous_approval_event_hash: Map.fetch!(attrs, :previous_approval_event_hash),
      approval_event_hash: Map.fetch!(attrs, :approval_event_hash),
      approved_by_user_id: Map.get(attrs, :approver_user_id),
      approved_by_device_id: Map.get(attrs, :approver_device_id),
      hybrid_signature: Map.get(attrs, :hybrid_signature),
      approved_at_ms: Map.get(attrs, :created_at_ms)
    }
  end

  defp pin_package_and_audit_or_rollback(candidate, package, bundle) do
    with {:ok, _entries} <- PackageEntries.pin_candidate_entries(candidate, package, bundle),
         {:ok, updated_package} <- Packages.pin_current(package, bundle),
         {:ok, _} <- Security.record_plugin_bundle_approved(bundle),
         {:ok, _} <- Security.record_plugin_bundle_promoted(bundle),
         :ok <- advance_existing_applications(updated_package, bundle) do
      updated_package
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp advance_existing_applications(package, bundle) do
    package.id
    |> applied_applications_for_package_update(bundle.workspace_id)
    |> Enum.reduce_while(:ok, fn application, :ok ->
      case advance_application_to_bundle(application, package, bundle) do
        {:ok, _updated} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp applied_applications_for_package_update(package_id, nil) do
    Repo.all(
      from(a in PluginApplication,
        where:
          a.package_id == ^package_id and not is_nil(a.current_bundle_id) and
            is_nil(a.deleted_at),
        order_by: [asc: a.plugin_id]
      )
    )
  end

  defp applied_applications_for_package_update(package_id, workspace_id) do
    Repo.all(
      from(a in PluginApplication,
        where:
          a.package_id == ^package_id and a.workspace_id == ^workspace_id and
            not is_nil(a.current_bundle_id) and is_nil(a.deleted_at),
        order_by: [asc: a.plugin_id]
      )
    )
  end

  defp advance_application_to_bundle(application, package, bundle) do
    application
    |> PluginApplication.changeset(%{
      current_bundle_id: bundle.id,
      state_head_hash: bundle.approval_event_hash,
      workspace_policy_result:
        Applications.workspace_policy_result(application.workspace_id, package, bundle)
    })
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        updated = Repo.preload(updated, :current_bundle, force: true)

        case Security.record_plugin_application_updated(updated) do
          {:ok, _} -> {:ok, updated}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp record_rejected(candidate, attrs, reason) do
    case Security.record_plugin_bundle_rejected(candidate, attrs, reason) do
      {:ok, _} -> {:error, reason}
      {:error, audit_reason} -> {:error, audit_reason}
    end
  end

  defp subject_source(bundle, candidate) do
    candidate
    |> Map.from_struct()
    |> Map.merge(%{
      workspace_id: bundle.workspace_id,
      application_id: bundle.application_id,
      package_id: bundle.package_id,
      owner_scope_kind: candidate.owner_scope_kind,
      owner_workspace_id: candidate.owner_workspace_id,
      owner_user_id: candidate.owner_user_id,
      plugin_id: bundle.plugin_id,
      version: bundle.version,
      bundle_hash: bundle.bundle_hash,
      manifest_hash: bundle.manifest_hash,
      main_js_hash: bundle.main_js_hash,
      styles_css_hash: bundle.styles_css_hash,
      resource_manifest_hash: bundle.resource_manifest_hash,
      permissions_hash: bundle.permissions_hash,
      endpoint_hash: bundle.endpoint_hash,
      renderer_slots_hash: bundle.renderer_slots_hash,
      document_scope_hash: bundle.document_scope_hash
    })
  end

  defp acquisition_hashes_match?(candidate, bundle) do
    Enum.all?(
      [
        :archive_hash,
        :source_kind,
        :source_url_hash,
        :permissions_hash,
        :endpoint_hash,
        :renderer_slots_hash,
        :document_scope_hash,
        :resource_manifest_hash
      ],
      &(Map.fetch!(candidate, &1) == Map.fetch!(bundle, &1))
    )
  end
end
