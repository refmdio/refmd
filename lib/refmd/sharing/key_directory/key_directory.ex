defmodule RefMD.Sharing.KeyDirectory do
  @moduledoc false

  alias RefMD.Crypto.{Blake3, JCS}
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory.PinBootstrap
  alias RefMD.Repo
  alias RefMD.Sharing.{Capability, Input}

  def validate_workspace_pin_bootstrap_hash(
        workspace_id,
        bootstrap,
        expected_hash,
        operation_sequence
      ) do
    with %{payload: _payload} = checkpoint <-
           Encryption.current_workspace_key_directory_checkpoint(workspace_id),
         :ok <- PinBootstrap.validate!(workspace_id, bootstrap, checkpoint, operation_sequence) do
      case PinBootstrap.hash!(workspace_id, bootstrap) do
        ^expected_hash -> :ok
        _ -> {:error, :workspace_pin_bootstrap_hash_mismatch}
      end
    else
      nil -> {:error, :workspace_key_directory_checkpoint_required}
    end
  rescue
    ArgumentError -> {:error, :workspace_pin_bootstrap_invalid}
  end

  def fetch_append(attrs) do
    events = dual_key_get(attrs, :workspace_key_directory_events)
    checkpoint = dual_key_get(attrs, :workspace_key_directory_checkpoint)

    if is_list(events) and events != [] and is_map(checkpoint),
      do: {:ok, events, checkpoint},
      else: {:error, :missing_key_directory}
  end

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  def share_created_event_ref(events) when is_list(events) do
    %{"payload" => %{"event_type" => "share_created", "sequence" => sequence} = payload} =
      Enum.find(events, &(get_in(&1, ["payload", "event_type"]) == "share_created"))

    if is_integer(sequence) and sequence > 0 do
      {:ok, %{hash: Blake3.hash_base64url(JCS.canonical_bytes!(payload)), sequence: sequence}}
    else
      {:error, :invalid_key_directory}
    end
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def share_created_event_ref(_), do: {:error, :invalid_key_directory}

  def share_created_event_hash(events) when is_list(events) do
    with {:ok, ref} <- share_created_event_ref(events), do: {:ok, ref.hash}
  end

  def share_created_event_hash(_), do: {:error, :invalid_key_directory}

  def share_created_capability_context_hash(events) when is_list(events) do
    %{"payload" => %{"event_type" => "share_created", "body" => body}} =
      Enum.find(events, &(get_in(&1, ["payload", "event_type"]) == "share_created"))

    Input.fetch_required_base64url_hash(body, :capability_context_hash)
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def share_created_capability_context_hash(_), do: {:error, :invalid_key_directory}

  def append!(%Document{} = document, attrs) do
    :ok = validate_body!(document, attrs)

    Encryption.append_workspace_key_directory!(
      document.workspace_id,
      attrs.key_directory_events,
      attrs.key_directory_checkpoint,
      checkpoint_signer_kind: "device"
    )

    :ok
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp validate_body!(document, attrs) do
    case Enum.find(
           attrs.key_directory_events,
           &(get_in(&1, ["payload", "event_type"]) == "share_created")
         ) do
      %{"payload" => %{"body" => body}} ->
        validate_share_created_body!(body, document, attrs)

      _ ->
        Repo.rollback(:invalid_key_directory)
    end
  end

  defp validate_share_created_body!(body, document, attrs) do
    checks = [
      workspace_id: body["workspace_id"] == document.workspace_id,
      share_id: body["share_id"] == attrs.share_id,
      scope_kind: body["scope_kind"] == attrs.scope,
      scope_id: body["scope_id"] == document.id,
      permission: body["permission"] == attrs.permission,
      password_protected: body["password_protected"] == attrs.password_protected,
      share_capability_secret_commitment:
        body["share_capability_secret_commitment"] == attrs.share_capability_secret_commitment,
      password_capability_secret_commitment:
        body["password_capability_secret_commitment"] ==
          attrs.password_capability_secret_commitment,
      capability_context_hash: body["capability_context_hash"] == attrs.capability_context_hash,
      capability_context_hash_recomputed:
        body["capability_context_hash"] == share_capability_context_hash(document, attrs, body),
      authorization_public_key_material:
        body["authorization_public_key_material"] == attrs.authorization_public_key_material,
      authorization_material_hash: authorization_material_hash_matches?(body, attrs),
      max_views: share_max_views_matches?(body["max_views"], attrs.max_views),
      expires_event_sequence:
        share_expires_event_sequence_matches?(
          body["expires_event_sequence"],
          attrs.expires_event_sequence
        )
    ]

    if Enum.all?(checks, fn {_label, ok} -> ok end),
      do: :ok,
      else: Repo.rollback(:invalid_key_directory)
  end

  defp authorization_material_hash_matches?(body, attrs) do
    body["authorization_public_key_material_hash"] ==
      Blake3.hash_base64url(JCS.canonical_bytes!(attrs.authorization_public_key_material))
  end

  defp share_capability_context_hash(document, attrs, body) do
    Capability.hash!(%{
      workspace_id: document.workspace_id,
      share_id: attrs.share_id,
      scope_kind: attrs.scope,
      scope_id: document.id,
      token_hash: attrs.token_hash,
      permission: attrs.permission,
      password_protected: attrs.password_protected,
      share_capability_secret_commitment: attrs.share_capability_secret_commitment,
      password_auth_metadata_hash: body["password_auth_metadata_hash"],
      password_capability_secret_commitment: attrs.password_capability_secret_commitment,
      workspace_pin_bootstrap_hash: attrs.authenticated_workspace_pin_bootstrap_hash,
      max_views: body["max_views"],
      redeem_authority_policy: body["redeem_authority_policy"]
    })
  end

  defp share_max_views_matches?(signed_max_views, attrs_max_views),
    do: signed_max_views == attrs_max_views

  defp share_expires_event_sequence_matches?(signed_sequence, attrs_sequence),
    do: signed_sequence == attrs_sequence
end
