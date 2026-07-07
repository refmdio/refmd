defmodule RefMD.Plugins.Bundles do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Plugins.{Applications, PluginApplication, PluginBundle, PluginBundleCandidate}
  alias RefMD.Repo

  def create(attrs) when is_map(attrs) do
    {:error, :plugin_bundle_candidate_required}
  end

  def list(application_id) do
    Repo.all(
      from(b in PluginBundle,
        where: b.application_id == ^application_id,
        order_by: [desc: b.created_at]
      )
    )
  end

  def pin_current(application, bundle), do: pin_current(application, bundle, [])

  def pin_current(%PluginApplication{} = application, %PluginBundle{} = bundle, opts) do
    with :ok <- validate_candidate_binding(bundle) do
      pin_candidate_backed_bundle(application, bundle, opts)
    end
  end

  def current_with_pin(_application_id, nil),
    do: {:error, :plugin_state_head_pin_required}

  def current_with_pin(application_id, trusted_state_head_hash)
      when is_binary(trusted_state_head_hash) do
    case Repo.get(PluginApplication, application_id) |> Repo.preload(:current_bundle) do
      nil ->
        {:error, :application_not_found}

      %PluginApplication{deleted_at: deleted_at} when not is_nil(deleted_at) ->
        {:error, :plugin_application_disabled}

      %PluginApplication{enabled: false} ->
        {:error, :plugin_application_disabled}

      %PluginApplication{} = application ->
        with :ok <- Applications.validate_runtime_policy(application) do
          current_bundle_with_pin(application, trusted_state_head_hash)
        end
    end
  end

  defp current_bundle_with_pin(
         %PluginApplication{current_bundle: nil},
         _trusted_state_head_hash
       ) do
    {:error, :plugin_bundle_not_pinned}
  end

  defp current_bundle_with_pin(
         %PluginApplication{state_head_hash: state_head_hash},
         trusted_state_head_hash
       )
       when state_head_hash != trusted_state_head_hash do
    {:error, :plugin_state_rollback}
  end

  defp current_bundle_with_pin(
         %PluginApplication{state_head_hash: state_head_hash, current_bundle: bundle},
         _trusted_state_head_hash
       ) do
    if bundle.approval_event_hash == state_head_hash do
      {:ok, bundle}
    else
      {:error, :plugin_state_rollback}
    end
  end

  defp validate_candidate_binding(%PluginBundle{candidate_id: nil}),
    do: {:error, :plugin_bundle_candidate_required}

  defp validate_candidate_binding(%PluginBundle{} = bundle) do
    case Repo.preload(bundle, :candidate).candidate do
      %PluginBundleCandidate{validation_status: "valid"} = candidate ->
        if candidate_binding_matches?(candidate, bundle) do
          :ok
        else
          {:error, :plugin_bundle_runtime_hash_mismatch}
        end

      %PluginBundleCandidate{} ->
        {:error, :plugin_bundle_candidate_invalid}

      nil ->
        {:error, :plugin_bundle_candidate_missing}
    end
  end

  defp candidate_binding_matches?(candidate, bundle) do
    Enum.all?(
      [
        :workspace_id,
        :plugin_id,
        :version,
        :source_kind,
        :source_url_hash,
        :archive_hash,
        :manifest_json,
        :bundle_hash,
        :manifest_hash,
        :main_js_hash,
        :styles_css_hash,
        :resource_manifest,
        :resource_manifest_hash,
        :permissions_hash,
        :endpoint_hash,
        :renderer_slots_hash,
        :document_scope_hash
      ],
      &(Map.fetch!(candidate, &1) == Map.fetch!(bundle, &1))
    )
  end

  defp pin_candidate_backed_bundle(
         %PluginApplication{} = application,
         %PluginBundle{} = bundle,
         opts
       ) do
    if bundle.application_id != application.id or
         bundle.workspace_id != application.workspace_id do
      {:error, :bundle_application_mismatch}
    else
      expected_state_head_hash = Keyword.get(opts, :expected_state_head_hash)

      case state_head_matches?(application, expected_state_head_hash) do
        true -> update_current_bundle(application, bundle)
        false -> {:error, :plugin_state_head_mismatch}
      end
    end
  end

  defp state_head_matches?(_application, nil), do: true

  defp state_head_matches?(%PluginApplication{} = application, expected_state_head_hash),
    do: application.state_head_hash == expected_state_head_hash

  defp update_current_bundle(application, bundle) do
    application
    |> PluginApplication.changeset(%{
      current_bundle_id: bundle.id,
      state_head_hash: bundle.approval_event_hash
    })
    |> Repo.update()
  end
end
