defmodule RefMD.Plugins.Consent do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Crypto.Signature.Plugin, as: PluginSignature

  alias RefMD.Plugins.{
    Artifact,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginConsentEvent,
    PluginPackage,
    Signing
  }

  alias RefMD.Repo
  alias RefMD.Security

  @genesis_event_hash "GENESIS"

  @type plugin_error ::
          :bundle_application_mismatch
          | :application_not_found
          | :plugin_bundle_not_pinned
          | :plugin_consent_event_hash_mismatch
          | :plugin_consent_event_signature_invalid
          | :plugin_consent_head_pin_required
          | :plugin_consent_not_allowed
          | :plugin_consent_rollback
          | :plugin_activation_disabled
          | :stale_consent_head
          | :invalid_consent_genesis

  @spec subject(map() | PluginConsentEvent.t()) :: map()
  def subject(%PluginConsentEvent{} = event), do: subject(Map.from_struct(event))

  def subject(attrs) when is_map(attrs) do
    attrs = put_runtime_identity_attrs(attrs)

    %{
      "plugin_id" => Map.fetch!(attrs, :plugin_id),
      "package_id" => Map.fetch!(attrs, :package_id),
      "application_id" => Map.fetch!(attrs, :application_id),
      "activation_id" => Map.fetch!(attrs, :activation_id),
      "owner_scope_kind" => Map.fetch!(attrs, :owner_scope_kind),
      "application_scope_kind" => Map.fetch!(attrs, :application_scope_kind),
      "version" => Map.fetch!(attrs, :version),
      "bundle_hash" => Map.fetch!(attrs, :bundle_hash),
      "manifest_hash" => Map.fetch!(attrs, :manifest_hash),
      "resource_manifest_hash" => Map.fetch!(attrs, :resource_manifest_hash),
      "permissions_hash" => Map.fetch!(attrs, :permissions_hash),
      "endpoint_hash" => Map.fetch!(attrs, :endpoint_hash),
      "document_scope_hash" => Map.fetch!(attrs, :document_scope_hash),
      "signer_device_id" => Map.fetch!(attrs, :signer_device_id),
      "signer_user_id" => Map.fetch!(attrs, :signer_user_id),
      "user_id" => Map.fetch!(attrs, :user_id),
      "device_id" => Map.fetch!(attrs, :device_id),
      "workspace_id" => Map.fetch!(attrs, :workspace_id),
      "consent_epoch" => Map.fetch!(attrs, :consent_epoch),
      "previous_event_hash" => Map.fetch!(attrs, :previous_event_hash),
      "decision" => Map.fetch!(attrs, :decision)
    }
  end

  @spec subject_hash(map() | PluginConsentEvent.t()) :: String.t()
  def subject_hash(attrs) do
    attrs
    |> subject()
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  @spec append_event(map()) ::
          {:ok, PluginConsentEvent.t()} | {:error, Ecto.Changeset.t() | plugin_error()}
  def append_event(attrs) when is_map(attrs) do
    attrs = put_runtime_identity_attrs(attrs)

    with {:ok, application} <- fetch_application(Map.get(attrs, :application_id)),
         {:ok, attrs} <- put_current_bundle_signer_attrs(attrs, application),
         :ok <- validate_permission_grant(attrs, application),
         :ok <- validate_event_hash(attrs),
         :ok <- validate_event_signature(attrs) do
      Repo.transaction(fn -> append_event_tx(attrs) end)
    end
  end

  defp put_runtime_identity_attrs(attrs) do
    attrs
    |> put_application_identity_attrs()
    |> put_activation_identity_attrs()
  end

  defp put_application_identity_attrs(%{application_id: application_id} = attrs)
       when is_binary(application_id) do
    case Repo.get(PluginApplication, application_id) |> Repo.preload(:package) do
      %PluginApplication{package: %PluginPackage{} = package} = application ->
        bundle = current_bundle(application)

        attrs
        |> Map.put(:package_id, package.id)
        |> Map.put(:owner_scope_kind, package.owner_scope_kind)
        |> Map.put(:application_scope_kind, application.application_scope_kind)
        |> Map.put(:workspace_id, application.workspace_id)
        |> Map.put(:plugin_id, application.plugin_id)
        |> maybe_put_bundle_resource_hash(bundle, package)

      _ ->
        attrs
    end
  end

  defp put_application_identity_attrs(attrs), do: attrs

  defp current_bundle(%PluginApplication{} = application) do
    application
    |> Repo.preload(:current_bundle)
    |> Map.get(:current_bundle)
  end

  defp maybe_put_bundle_resource_hash(
         attrs,
         %PluginBundle{resource_manifest_hash: hash},
         _package
       )
       when is_binary(hash),
       do: Map.put(attrs, :resource_manifest_hash, hash)

  defp maybe_put_bundle_resource_hash(attrs, _bundle, %PluginPackage{resource_manifest_hash: hash})
       when is_binary(hash),
       do: Map.put(attrs, :resource_manifest_hash, hash)

  defp maybe_put_bundle_resource_hash(attrs, _bundle, _package), do: attrs

  defp put_activation_identity_attrs(
         %{application_id: application_id, user_id: user_id, device_id: device_id} = attrs
       )
       when is_binary(application_id) and is_binary(user_id) and is_binary(device_id) do
    case activation_for(application_id, user_id, device_id) do
      %PluginActivation{id: id} ->
        Map.put(attrs, :activation_id, id)

      nil ->
        case Repo.insert(
               PluginActivation.changeset(%PluginActivation{}, %{
                 application_id: application_id,
                 user_id: user_id,
                 device_id: device_id,
                 activation_scope_kind: "device",
                 enabled: true
               })
             ) do
          {:ok, activation} -> Map.put(attrs, :activation_id, activation.id)
          {:error, _changeset} -> attrs
        end
    end
  end

  defp put_activation_identity_attrs(attrs), do: attrs

  defp activation_for(application_id, user_id, device_id) do
    Repo.one(
      from(a in PluginActivation,
        where:
          a.application_id == ^application_id and a.user_id == ^user_id and
            a.device_id == ^device_id and is_nil(a.deleted_at),
        order_by: [desc: a.created_at],
        limit: 1
      )
    )
  end

  @spec latest_event(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t()) :: PluginConsentEvent.t() | nil
  def latest_event(application_id, user_id, device_id) do
    application_id
    |> latest_event_query(user_id, device_id)
    |> Repo.one()
  end

  @spec allowed_with_pin(Ecto.UUID.t(), Ecto.UUID.t(), Ecto.UUID.t(), String.t() | nil) ::
          {:ok, PluginConsentEvent.t()}
          | {:error,
             :not_found
             | :plugin_consent_head_pin_required
             | :plugin_consent_rollback
             | :plugin_consent_not_allowed
             | :plugin_activation_disabled}
  def allowed_with_pin(_application_id, _user_id, _device_id, nil),
    do: {:error, :plugin_consent_head_pin_required}

  def allowed_with_pin(application_id, user_id, device_id, trusted_head_hash)
      when is_binary(trusted_head_hash) do
    case latest_event(application_id, user_id, device_id) do
      nil ->
        {:error, :not_found}

      %PluginConsentEvent{event_hash: event_hash} when event_hash != trusted_head_hash ->
        {:error, :plugin_consent_rollback}

      %PluginConsentEvent{decision: "allow"} = event ->
        with :ok <- validate_activation_enabled(event), do: {:ok, event}

      %PluginConsentEvent{} ->
        {:error, :plugin_consent_not_allowed}
    end
  end

  defp validate_activation_enabled(%PluginConsentEvent{} = event) do
    case Repo.get(PluginActivation, event.activation_id) do
      %PluginActivation{
        enabled: true,
        deleted_at: nil,
        application_id: application_id,
        user_id: user_id,
        device_id: activation_device_id
      }
      when application_id == event.application_id and user_id == event.user_id and
             (activation_device_id == event.device_id or is_nil(activation_device_id)) ->
        :ok

      %PluginActivation{} ->
        {:error, :plugin_activation_disabled}

      nil ->
        {:error, :plugin_activation_disabled}
    end
  end

  @spec validate_bundle_binding(PluginBundle.t(), PluginConsentEvent.t()) ::
          :ok | {:error, :plugin_consent_rollback}
  def validate_bundle_binding(%PluginBundle{} = bundle, %PluginConsentEvent{} = consent) do
    if matches_bundle?(bundle, consent) do
      :ok
    else
      {:error, :plugin_consent_rollback}
    end
  end

  @spec matches_bundle?(PluginBundle.t(), PluginConsentEvent.t() | nil) :: boolean()
  def matches_bundle?(%PluginBundle{} = bundle, %PluginConsentEvent{} = consent) do
    identity_matches?(consent, bundle) and
      semantics_match?(consent, bundle) and
      approval_signer_matches?(consent, bundle)
  end

  def matches_bundle?(_bundle, _consent), do: false

  @spec proof(PluginConsentEvent.t()) ::
          {:ok, map()} | {:error, :plugin_consent_event_signature_invalid}
  def proof(%PluginConsentEvent{} = consent) do
    case Signing.fetch_active_device(consent.user_id, consent.device_id) do
      {:ok, device} ->
        {:ok,
         %{
           event_hash: consent.event_hash,
           subject: subject(consent),
           actor: Signing.actor(device, consent.workspace_id),
           hybrid_signature: consent.hybrid_signature,
           signing_key_id: device.signing_key_id
         }}

      _ ->
        {:error, :plugin_consent_event_signature_invalid}
    end
  end

  defp fetch_application(nil), do: {:error, :application_not_found}

  defp fetch_application(application_id) do
    case Repo.get(PluginApplication, application_id) do
      nil -> {:error, :application_not_found}
      application -> {:ok, application}
    end
  end

  defp validate_permission_grant(attrs, application) do
    application = Repo.preload(application, :current_bundle)

    case application.current_bundle do
      nil ->
        {:error, :plugin_bundle_not_pinned}

      %PluginBundle{} = bundle ->
        with :ok <- validate_current_bundle(attrs, bundle) do
          Artifact.validate_manifest_permission_grant(runtime_manifest(bundle))
        end
    end
  end

  defp put_current_bundle_signer_attrs(attrs, application) do
    application = Repo.preload(application, :current_bundle)

    case application.current_bundle do
      nil ->
        {:error, :plugin_bundle_not_pinned}

      %PluginBundle{} = bundle ->
        {:ok,
         attrs
         |> Map.put(:signer_user_id, bundle.approved_by_user_id)
         |> Map.put(:signer_device_id, bundle.approved_by_device_id)}
    end
  end

  defp validate_current_bundle(attrs, bundle) do
    if identity_matches?(attrs, bundle) and
         semantics_match?(attrs, bundle) and
         approval_signer_matches?(attrs, bundle) do
      :ok
    else
      {:error, :plugin_consent_rollback}
    end
  end

  defp identity_matches?(attrs, bundle) do
    runtime_binding_matches?(attrs, bundle) and
      Map.get(attrs, :package_id) == bundle.package_id and
      Map.get(attrs, :plugin_id) == bundle.plugin_id and
      Map.get(attrs, :version) == bundle.version
  end

  defp runtime_binding_matches?(attrs, %PluginBundle{
         application_id: nil,
         workspace_id: nil
       }) do
    is_binary(Map.get(attrs, :application_id)) and is_binary(Map.get(attrs, :workspace_id))
  end

  defp runtime_binding_matches?(attrs, %PluginBundle{
         application_id: nil,
         workspace_id: workspace_id
       })
       when is_binary(workspace_id) do
    is_binary(Map.get(attrs, :application_id)) and Map.get(attrs, :workspace_id) == workspace_id
  end

  defp runtime_binding_matches?(attrs, bundle) do
    Map.get(attrs, :workspace_id) == bundle.workspace_id and
      Map.get(attrs, :application_id) == bundle.application_id
  end

  defp semantics_match?(attrs, bundle) do
    Map.get(attrs, :bundle_hash) == bundle.bundle_hash and
      Map.get(attrs, :manifest_hash) == bundle.manifest_hash and
      Map.get(attrs, :resource_manifest_hash) == bundle.resource_manifest_hash and
      Map.get(attrs, :permissions_hash) == bundle.permissions_hash and
      Map.get(attrs, :endpoint_hash) == bundle.endpoint_hash and
      Map.get(attrs, :document_scope_hash) == bundle.document_scope_hash
  end

  defp approval_signer_matches?(attrs, bundle) do
    Map.get(attrs, :signer_user_id) == bundle.approved_by_user_id and
      Map.get(attrs, :signer_device_id) == bundle.approved_by_device_id
  end

  defp validate_event_hash(attrs) do
    if Map.get(attrs, :event_hash) == subject_hash(attrs) do
      :ok
    else
      {:error, :plugin_consent_event_hash_mismatch}
    end
  end

  defp validate_event_signature(attrs) do
    signer_user_id = Map.get(attrs, :user_id)
    signer_device_id = Map.get(attrs, :device_id)
    consent = subject(attrs)

    with {:ok, device} <- Signing.fetch_active_device(signer_user_id, signer_device_id),
         actor = Signing.actor(device, Map.fetch!(attrs, :workspace_id)),
         transcript <-
           PluginSignature.build_plugin_consent_event_transcript!(%{
             actor: actor,
             consent: consent
           }),
         :ok <-
           Signing.verify(
             "plugin_consent_event",
             transcript,
             Map.get(attrs, :hybrid_signature),
             device,
             %{actor: actor, consent_subject: consent}
           ) do
      :ok
    else
      _ -> {:error, :plugin_consent_event_signature_invalid}
    end
  rescue
    ArgumentError -> {:error, :plugin_consent_event_signature_invalid}
  end

  defp runtime_manifest(%PluginBundle{} = bundle) when is_map(bundle.manifest_json),
    do: bundle.manifest_json

  defp runtime_manifest(_bundle), do: %{}

  defp append_event_tx(attrs) do
    latest =
      latest_event_query(
        Map.fetch!(attrs, :application_id),
        Map.fetch!(attrs, :user_id),
        Map.fetch!(attrs, :device_id)
      )
      |> lock("FOR UPDATE")
      |> Repo.one()

    case validate_chain(latest, attrs) do
      :ok -> insert_event(attrs)
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp insert_event(attrs) do
    %PluginConsentEvent{}
    |> PluginConsentEvent.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, event} ->
        case Security.record_plugin_consent_event(event) do
          {:ok, _} -> event
          {:error, reason} -> Repo.rollback(reason)
        end

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp latest_event_query(application_id, user_id, device_id) do
    from(e in PluginConsentEvent,
      where:
        e.application_id == ^application_id and e.user_id == ^user_id and
          e.device_id == ^device_id,
      order_by: [desc: e.consent_epoch],
      limit: 1
    )
  end

  defp validate_chain(nil, attrs) do
    if Map.get(attrs, :previous_event_hash) == @genesis_event_hash do
      :ok
    else
      {:error, :invalid_consent_genesis}
    end
  end

  defp validate_chain(%PluginConsentEvent{} = latest, attrs) do
    previous_event_hash = Map.get(attrs, :previous_event_hash)
    consent_epoch = Map.get(attrs, :consent_epoch)

    if previous_event_hash == latest.event_hash and consent_epoch > latest.consent_epoch do
      :ok
    else
      {:error, :stale_consent_head}
    end
  end
end
