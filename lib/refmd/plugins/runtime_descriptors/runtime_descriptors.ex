defmodule RefMD.Plugins.RuntimeDescriptors do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Plugins.{
    Activations,
    Applications,
    Consent,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginConsentEvent
  }

  alias RefMD.Repo

  @spec list(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: [map()]
  def list(workspace_id, user_id, device_id) do
    Applications.ensure_personal_workspace_applications(workspace_id, user_id, device_id)

    workspace_id
    |> enabled_applications_with_current_bundle()
    |> Enum.flat_map(&runtime_descriptor(&1, user_id, device_id))
  end

  @spec list_consent_required(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: [map()]
  def list_consent_required(workspace_id, user_id, device_id) do
    Applications.ensure_personal_workspace_applications(workspace_id, user_id, device_id)

    workspace_id
    |> enabled_applications_with_current_bundle()
    |> Enum.flat_map(&consent_required_descriptor(&1, user_id, device_id))
  end

  defp enabled_applications_with_current_bundle(workspace_id) do
    PluginApplication
    |> where([i], i.workspace_id == ^workspace_id and i.enabled == true)
    |> where([i], is_nil(i.deleted_at))
    |> where([i], i.workspace_policy_result == "allowed")
    |> where([i], not is_nil(i.current_bundle_id))
    |> preload(current_bundle: :candidate)
    |> order_by([i], asc: i.plugin_id)
    |> Repo.all()
  end

  defp runtime_descriptor(
         %PluginApplication{current_bundle: %PluginBundle{} = bundle} = application,
         user_id,
         device_id
       ) do
    activation = Activations.latest_for_actor(application.id, user_id, device_id)
    consent = Consent.latest_event(application.id, user_id, device_id)

    if activation_enabled?(activation) and
         runtime_descriptor_allowed?(bundle, activation, consent) do
      [descriptor_payload(application, bundle, activation, consent, user_id, device_id)]
    else
      []
    end
  end

  defp runtime_descriptor(_application, _user_id, _device_id), do: []

  defp consent_required_descriptor(
         %PluginApplication{current_bundle: %PluginBundle{} = bundle} = application,
         user_id,
         device_id
       ) do
    case Activations.latest_for_actor(application.id, user_id, device_id) do
      %PluginActivation{deleted_at: nil} = activation ->
        consent_required_descriptor_for_activation(
          application,
          bundle,
          activation,
          user_id,
          device_id
        )

      %PluginActivation{} ->
        []

      nil ->
        create_consent_required_descriptor(application, bundle, user_id, device_id)
    end
  end

  defp consent_required_descriptor(_application, _user_id, _device_id), do: []

  defp consent_required_descriptor_for_activation(
         application,
         bundle,
         activation,
         user_id,
         device_id
       ) do
    consent = Consent.latest_event(application.id, user_id, device_id)

    cond do
      activation_enabled?(activation) and runtime_descriptor_allowed?(bundle, activation, consent) ->
        []

      current_consent_tombstone?(bundle, activation, consent) ->
        []

      true ->
        [descriptor_payload(application, bundle, activation, consent, user_id, device_id)]
    end
  end

  defp create_consent_required_descriptor(application, bundle, user_id, device_id) do
    case Activations.get_or_create_application(application.id, user_id, device_id) do
      {:ok, activation} ->
        consent = Consent.latest_event(application.id, user_id, device_id)
        [descriptor_payload(application, bundle, activation, consent, user_id, device_id)]

      {:error, _reason} ->
        []
    end
  end

  defp runtime_descriptor_allowed?(
         bundle,
         %PluginActivation{} = activation,
         %PluginConsentEvent{decision: "allow"} = consent
       ),
       do: consent.activation_id == activation.id and Consent.matches_bundle?(bundle, consent)

  defp runtime_descriptor_allowed?(_bundle, _activation, _consent), do: false

  defp current_consent_tombstone?(
         %PluginBundle{} = bundle,
         %PluginActivation{} = activation,
         %PluginConsentEvent{decision: decision} = consent
       )
       when decision in ["deny", "revoke"] do
    consent.activation_id == activation.id and Consent.matches_bundle?(bundle, consent)
  end

  defp current_consent_tombstone?(_bundle, _activation, _consent), do: false

  defp activation_enabled?(%{enabled: true, deleted_at: nil}), do: true
  defp activation_enabled?(_activation), do: false

  defp descriptor_payload(application, bundle, activation, consent, user_id, device_id) do
    manifest = runtime_manifest(bundle)

    %{
      plugin_id: application.plugin_id,
      package_id: application.package_id,
      application_id: application.id,
      activation_id: activation_id(activation),
      capability_grant_id:
        runtime_capability_grant_id(application, bundle, activation, consent, user_id, device_id),
      owner_scope_kind: owner_scope_kind(application),
      application_scope_kind: application.application_scope_kind,
      workspace_id: application.workspace_id,
      state_head_hash: application.state_head_hash,
      consent_head_hash: consent_event_hash(consent),
      consent_epoch: consent_epoch(consent),
      version: bundle.version,
      bundle_hash: bundle.bundle_hash,
      approval_event_hash: bundle.approval_event_hash,
      manifest_hash: bundle.manifest_hash,
      resource_manifest_hash: bundle.resource_manifest_hash,
      permissions_hash: bundle.permissions_hash,
      endpoint_hash: bundle.endpoint_hash,
      renderer_slots_hash: bundle.renderer_slots_hash,
      document_scope_hash: bundle.document_scope_hash,
      signer_user_id: bundle.approved_by_user_id,
      signer_device_id: bundle.approved_by_device_id,
      title: manifest_title(manifest, application.plugin_id),
      author: manifest_author(manifest),
      permissions: manifest_permissions(manifest),
      document_scope: manifest_document_scope(manifest),
      network_endpoints: manifest_network_endpoints(manifest),
      renderer_slots: manifest_renderer_slots(manifest),
      document_scopes: manifest_document_scopes(manifest),
      high_risk_consents: inferred_high_risk_consents(manifest)
    }
  end

  @spec capability_grant_id(
          PluginApplication.t(),
          PluginBundle.t(),
          PluginActivation.t() | nil,
          PluginConsentEvent.t() | nil,
          Ecto.UUID.t(),
          Ecto.UUID.t() | nil
        ) :: Ecto.UUID.t()
  def capability_grant_id(application, bundle, activation, consent, user_id, device_id) do
    runtime_capability_grant_id(application, bundle, activation, consent, user_id, device_id)
  end

  defp activation_id(%{id: id}), do: id
  defp activation_id(_activation), do: nil

  defp runtime_capability_grant_id(application, bundle, activation, consent, user_id, device_id) do
    deterministic_uuid([
      "runtime-capability-grant",
      application.package_id,
      application.id,
      activation_id(activation),
      user_id,
      device_id,
      application.state_head_hash,
      bundle.bundle_hash,
      consent_event_hash(consent),
      consent_epoch(consent)
    ])
  end

  defp deterministic_uuid(parts) do
    hash = :crypto.hash(:sha256, :erlang.term_to_binary(parts))

    <<prefix::binary-size(6), _version::4, middle::12, _variant::2, suffix::62, _rest::binary>> =
      hash

    bytes = <<prefix::binary, 5::4, middle::12, 2::2, suffix::62>>
    {:ok, uuid} = Ecto.UUID.load(bytes)
    uuid
  end

  defp owner_scope_kind(%PluginApplication{} = application) do
    application
    |> Repo.preload(:package)
    |> Map.get(:package)
    |> case do
      %{owner_scope_kind: owner_scope_kind} -> owner_scope_kind
      _ -> "workspace"
    end
  end

  defp consent_event_hash(%PluginConsentEvent{} = consent), do: consent.event_hash
  defp consent_event_hash(_consent), do: nil

  defp consent_epoch(%PluginConsentEvent{} = consent), do: consent.consent_epoch
  defp consent_epoch(_consent), do: nil

  defp runtime_manifest(%PluginBundle{} = bundle) when is_map(bundle.manifest_json),
    do: bundle.manifest_json

  defp runtime_manifest(_bundle), do: %{}

  defp manifest_title(manifest, fallback) when is_map(manifest) do
    case Map.get(manifest, "name") do
      value when is_binary(value) and value != "" -> value
      _ -> fallback
    end
  end

  defp manifest_title(_manifest, fallback), do: fallback

  defp manifest_author(%{"author" => value}) when is_binary(value) and value != "",
    do: value

  defp manifest_author(_manifest), do: "Unknown author"

  defp manifest_permissions(%{"permissions" => permissions}) when is_list(permissions) do
    Enum.filter(permissions, &is_binary/1)
  end

  defp manifest_permissions(_manifest), do: []

  defp manifest_document_scope(%{"documentScopes" => scopes}) when is_list(scopes) do
    scopes
    |> Enum.reduce(%{}, &merge_document_scope/2)
    |> drop_empty_document_scope()
  end

  defp manifest_document_scope(_manifest), do: %{}

  defp manifest_document_scopes(%{"documentScopes" => scopes}) when is_list(scopes), do: scopes
  defp manifest_document_scopes(_manifest), do: []

  defp merge_document_scope(%{"kind" => "workspace"}, acc),
    do: Map.put(acc, "workspaceReadAllowed", true)

  defp merge_document_scope(%{"kind" => kind} = scope, acc)
       when kind in ["active_document", "activeDocument", "active"] do
    case document_scope_id(scope) do
      document_id when document_id in [nil, "active", "active_document", "activeDocument"] ->
        Map.put(acc, "activeDocumentReadAllowed", true)

      document_id ->
        acc
        |> Map.put("activeDocumentReadAllowed", true)
        |> Map.put("activeDocumentId", document_id)
    end
  end

  defp merge_document_scope(%{"kind" => kind} = scope, acc)
       when kind in ["selected_documents", "selectedDocuments", "selected"] do
    case document_scope_ids(scope) do
      [] ->
        Map.put(acc, "selectedDocumentsReadAllowed", true)

      document_ids ->
        semantic_ids = ["selected", "selected_documents", "selectedDocuments"]

        if Enum.all?(document_ids, &(&1 in semantic_ids)) do
          Map.put(acc, "selectedDocumentsReadAllowed", true)
        else
          acc
          |> Map.put("selectedDocumentsReadAllowed", true)
          |> Map.put("selectedDocumentIds", Enum.reject(document_ids, &(&1 in semantic_ids)))
        end
    end
  end

  defp merge_document_scope(%{"kind" => kind} = scope, acc)
       when kind in ["allowed_documents", "allowedDocuments", "allowed_document", "document"] do
    case document_scope_ids(scope) do
      [] -> acc
      document_ids -> Map.put(acc, "allowedDocumentIds", document_ids)
    end
  end

  defp merge_document_scope(_scope, acc), do: acc

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
      fn key ->
        Map.get(scope, key)
      end
    )
  end

  defp drop_empty_document_scope(scope) when map_size(scope) == 0, do: %{}
  defp drop_empty_document_scope(scope), do: scope

  defp manifest_network_endpoints(%{"network" => %{"endpoints" => endpoints}})
       when is_list(endpoints) do
    endpoints
    |> Enum.flat_map(&manifest_network_endpoint/1)
  end

  defp manifest_network_endpoints(_manifest), do: []

  defp manifest_renderer_slots(%{"rendererSlots" => slots}) when is_list(slots) do
    Enum.flat_map(slots, &manifest_renderer_slot/1)
  end

  defp manifest_renderer_slots(_manifest), do: []

  defp manifest_renderer_slot(%{"kind" => kind, "type" => type})
       when kind == "block" and is_binary(type) and type != "" do
    [%{"kind" => kind, "type" => type}]
  end

  defp manifest_renderer_slot(%{"kind" => "inline", "type" => "code"}) do
    [%{"kind" => "inline", "type" => "code"}]
  end

  defp manifest_renderer_slot(_slot), do: []

  defp manifest_network_endpoint(%{"id" => id, "url" => url} = endpoint)
       when is_binary(id) and is_binary(url) do
    [
      %{
        "id" => id,
        "url" => url,
        "methods" => endpoint_string_list(endpoint, "methods"),
        "routes" => endpoint_string_list(endpoint, "routes"),
        "headers" => endpoint_string_list(endpoint, "headers", "allowedHeaders"),
        "bodySchema" => endpoint_body_schema(endpoint),
        "maxRequestBytes" => endpoint_byte_limit(endpoint, "maxRequestBytes", 65_536),
        "maxResponseBytes" => endpoint_byte_limit(endpoint, "maxResponseBytes", 524_288),
        "credentialAudience" => endpoint_string(endpoint, "credentialAudience")
      }
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()
    ]
  end

  defp manifest_network_endpoint(_endpoint), do: []

  defp endpoint_string_list(endpoint, primary_key, secondary_key \\ nil) do
    value =
      case Map.get(endpoint, primary_key) do
        value when is_list(value) -> value
        _ when is_binary(secondary_key) -> Map.get(endpoint, secondary_key)
        _ -> []
      end

    value
    |> List.wrap()
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
  end

  defp endpoint_body_schema(%{"bodySchema" => value}) when value in ["none", "json", "text"],
    do: value

  defp endpoint_body_schema(_endpoint), do: "none"

  defp endpoint_byte_limit(endpoint, key, fallback) do
    case Map.get(endpoint, key) do
      value when is_integer(value) and value > 0 -> value
      _ -> fallback
    end
  end

  defp endpoint_string(endpoint, key) do
    case Map.get(endpoint, key) do
      value when is_binary(value) and value != "" -> value
      _ -> nil
    end
  end

  defp inferred_high_risk_consents(manifest) when is_map(manifest) do
    permissions = manifest_permissions(manifest)
    plaintext_read? = Enum.any?(permissions, &plaintext_read_permission?/1)
    network_fetch? = "network:fetch" in permissions
    cache_storage_write? = "storage:write:cache" in permissions
    workspace_read? = "document:read:workspace" in permissions
    document_write? = "document:write" in permissions

    [
      if(plaintext_read? and document_write?, do: "plaintext_document_write"),
      if(plaintext_read? and network_fetch?, do: "plaintext_network_egress"),
      if(plaintext_read? and cache_storage_write?, do: "plaintext_cache_storage"),
      if(workspace_read? and network_fetch?, do: "workspace_network_egress")
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp inferred_high_risk_consents(_manifest), do: []

  defp plaintext_read_permission?("document:read:" <> scope)
       when scope in ["active", "selected", "workspace"],
       do: true

  defp plaintext_read_permission?("plaintext:render:" <> _scope), do: true
  defp plaintext_read_permission?("editor:selection:read"), do: true
  defp plaintext_read_permission?("editor:context:read"), do: true
  defp plaintext_read_permission?(_permission), do: false
end
