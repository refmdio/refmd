defmodule RefMD.Plugins.RuntimeBundles do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Encryption.KeyDirectory

  alias RefMD.Plugins.{
    Approvals,
    Artifact,
    Bundles,
    Consent,
    PackageEntries,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginPackage,
    RuntimeDescriptors
  }

  alias RefMD.Repo

  @type plugin_error ::
          :application_not_found
          | :not_found
          | :plugin_bundle_candidate_missing
          | :plugin_bundle_not_pinned
          | :plugin_bundle_runtime_hash_mismatch
          | :plugin_consent_head_pin_required
          | :plugin_consent_not_allowed
          | :plugin_consent_rollback
          | :plugin_application_disabled
          | :plugin_activation_disabled
          | :plugin_workspace_policy_denied
          | :plugin_state_head_pin_required
          | :plugin_state_rollback

  @spec with_pins(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t() | nil,
          String.t() | nil
        ) :: {:ok, map()} | {:error, plugin_error()}
  def with_pins(
        runtime_target_id,
        workspace_id,
        user_id,
        device_id,
        trusted_state_head_hash,
        trusted_consent_head_hash
      ) do
    with %PluginApplication{} = application <- Repo.get(PluginApplication, runtime_target_id),
         :ok <- application_workspace_matches(application, workspace_id),
         {:ok, bundle} <- Bundles.current_with_pin(application.id, trusted_state_head_hash),
         {:ok, consent} <-
           Consent.allowed_with_pin(
             application.id,
             user_id,
             device_id,
             trusted_consent_head_hash
           ),
         {:ok, activation} <- current_activation(consent),
         :ok <- Consent.validate_bundle_binding(bundle, consent),
         {:ok, entries} <- load_entries(bundle),
         bytes = bytes_by_path(entries),
         :ok <- validate_bytes(bundle, entries, bytes),
         {:ok, approval_proof} <- Approvals.proof(bundle),
         {:ok, approval_authority_evidence} <- approval_authority_evidence(approval_proof),
         {:ok, consent_proof} <- Consent.proof(consent) do
      {:ok,
       payload(application, bundle, entries, bytes, %{
         consent: consent,
         activation: activation,
         user_id: user_id,
         device_id: device_id,
         trusted_state_head_hash: trusted_state_head_hash,
         approval_proof: approval_proof,
         approval_authority_evidence: approval_authority_evidence,
         consent_proof: consent_proof
       })}
    else
      nil -> {:error, :application_not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  defp application_workspace_matches(
         %PluginApplication{workspace_id: workspace_id},
         workspace_id
       ),
       do: :ok

  defp application_workspace_matches(%PluginApplication{}, _workspace_id),
    do: {:error, :application_not_found}

  defp load_entries(%PluginBundle{} = bundle), do: PackageEntries.bundle_entries(bundle.id)

  defp validate_bytes(%PluginBundle{} = bundle, entries, bytes) do
    if hashes_match?(bundle, entries, bytes) do
      :ok
    else
      {:error, :plugin_bundle_runtime_hash_mismatch}
    end
  end

  defp hashes_match?(bundle, entries, bytes) do
    main_js = Map.get(bytes, "main.js")
    styles_css = Map.get(bytes, "styles.css", "")
    manifest_json_bytes = Map.get(bytes, "manifest.json")

    is_binary(main_js) and is_binary(styles_css) and is_binary(manifest_json_bytes) and
      Hash.blake3_base64url(main_js) == bundle.main_js_hash and
      Hash.blake3_base64url(styles_css) == bundle.styles_css_hash and
      Hash.blake3_base64url(manifest_json_bytes) == bundle.manifest_hash and
      resources_match_manifest?(bundle, entries) and
      Artifact.bundle_hash_from_hashes(
        bundle.manifest_hash,
        bundle.main_js_hash,
        bundle.styles_css_hash,
        bundle.resource_manifest_hash
      ) ==
        bundle.bundle_hash
  end

  defp payload(
         application,
         bundle,
         entries,
         bytes,
         context
       ) do
    consent = Map.fetch!(context, :consent)
    activation = Map.fetch!(context, :activation)
    package = Repo.get!(PluginPackage, bundle.package_id)

    %{
      plugin_id: bundle.plugin_id,
      package_id: bundle.package_id,
      bundle_id: bundle.id,
      application_id: application.id,
      activation_id: consent.activation_id,
      owner_scope_kind: package.owner_scope_kind,
      capability_grant_id:
        RuntimeDescriptors.capability_grant_id(
          application,
          bundle,
          activation,
          consent,
          Map.fetch!(context, :user_id),
          Map.fetch!(context, :device_id)
        ),
      workspace_id: application.workspace_id,
      version: bundle.version,
      bundle_hash: bundle.bundle_hash,
      manifest_hash: bundle.manifest_hash,
      main_js_hash: bundle.main_js_hash,
      styles_css_hash: bundle.styles_css_hash,
      resource_manifest: bundle.resource_manifest,
      resource_manifest_hash: bundle.resource_manifest_hash,
      permissions_hash: bundle.permissions_hash,
      endpoint_hash: bundle.endpoint_hash,
      renderer_slots_hash: bundle.renderer_slots_hash,
      document_scope_hash: bundle.document_scope_hash,
      approval_event_hash: bundle.approval_event_hash,
      consent_event_hash: consent.event_hash,
      consent_epoch: consent.consent_epoch,
      state_head_hash: Map.fetch!(context, :trusted_state_head_hash),
      approval_proof:
        Map.fetch!(context, :approval_proof)
        |> Map.merge(Map.fetch!(context, :approval_authority_evidence)),
      consent_proof: Map.fetch!(context, :consent_proof),
      manifest_json: bundle.manifest_json,
      manifest_json_bytes: Map.fetch!(bytes, "manifest.json"),
      main_js: Map.fetch!(bytes, "main.js"),
      styles_css: Map.get(bytes, "styles.css", ""),
      resources: resource_payload_entries(entries)
    }
  end

  defp approval_authority_evidence(%{approval_authority: authority})
       when is_map(authority) do
    scope_kind = Map.get(authority, "scope_kind")
    scope_id = authority_scope_id(authority)
    checkpoint_sequence = Map.get(authority, "checkpoint_sequence")
    event_head_sequence = Map.get(authority, "event_head_sequence")

    with true <- scope_kind in ["user", "workspace"],
         true <- is_binary(scope_id),
         true <- is_integer(checkpoint_sequence) and checkpoint_sequence > 0,
         true <- is_integer(event_head_sequence) and event_head_sequence > 0,
         [checkpoint] <-
           KeyDirectory.checkpoints_between(
             scope_kind,
             scope_id,
             checkpoint_sequence,
             checkpoint_sequence
           ),
         :ok <- KeyDirectory.assert_stored_checkpoint!(checkpoint) do
      events =
        scope_kind
        |> KeyDirectory.events_after_until(scope_id, 0, event_head_sequence)
        |> Enum.map(fn event ->
          :ok = KeyDirectory.assert_stored_event!(event)
          serialize_key_directory_event(event)
        end)

      {:ok,
       %{
         approval_authority_checkpoint: serialize_key_directory_checkpoint(checkpoint),
         approval_authority_event_ancestry: events
       }}
    else
      _ -> {:error, :plugin_bundle_approval_forbidden}
    end
  end

  defp authority_scope_id(%{"scope_kind" => "workspace", "workspace_id" => workspace_id}),
    do: workspace_id

  defp authority_scope_id(%{"scope_kind" => "user", "owner_user_id" => user_id}), do: user_id

  defp authority_scope_id(_), do: nil

  defp serialize_key_directory_checkpoint(checkpoint) do
    %{
      payload: checkpoint.payload,
      signatures: checkpoint.signatures
    }
  end

  defp serialize_key_directory_event(event) do
    %{
      payload: event.payload,
      signatures: event.signatures
    }
  end

  defp current_activation(consent) do
    case Repo.get(PluginActivation, consent.activation_id) do
      %PluginActivation{enabled: true, deleted_at: nil} = activation -> {:ok, activation}
      %PluginActivation{} -> {:error, :plugin_activation_disabled}
      nil -> {:error, :plugin_activation_disabled}
    end
  end

  defp bytes_by_path(entries) do
    Map.new(entries, fn %{entry: entry, bytes: bytes} -> {entry.logical_path, bytes} end)
  end

  defp resources_match_manifest?(bundle, entries) do
    manifest = resource_manifest_from_entries(entries)

    manifest == bundle.resource_manifest and
      Hash.blake3_base64url(JCS.canonical_value_bytes!(manifest)) == bundle.resource_manifest_hash
  end

  defp resource_manifest_from_entries(entries) do
    entries
    |> Enum.filter(&(&1.entry.entry_kind == "resource"))
    |> Enum.map(fn %{entry: entry} ->
      %{
        "path" => entry.logical_path,
        "kind" => entry.resource_kind,
        "media_type" => entry.media_type,
        "byte_length" => entry.byte_length,
        "hash" => entry.hash,
        "executable" => entry.resource_kind == "wasm"
      }
    end)
    |> Enum.sort_by(&Map.fetch!(&1, "path"))
  end

  defp resource_payload_entries(entries) do
    entries
    |> Enum.filter(&(&1.entry.entry_kind == "resource"))
    |> Enum.map(fn %{entry: entry, bytes: bytes} ->
      %{
        path: entry.logical_path,
        kind: entry.resource_kind,
        media_type: entry.media_type,
        byte_length: entry.byte_length,
        hash: entry.hash,
        bytes: bytes
      }
    end)
  end
end
