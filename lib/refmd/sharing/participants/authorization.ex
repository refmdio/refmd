defmodule RefMD.Sharing.Participants.Authorization do
  @moduledoc false

  alias RefMD.Crypto.{HybridEncryptionMaterial, Signature}
  alias RefMD.Sharing.Share

  @spec attach_verified(Share.t(), map()) :: {:ok, map()} | {:error, term()}
  def attach_verified(%Share{} = share, authorization) when is_map(authorization) do
    with {:ok, principal_id} <- fetch_uuid(authorization, :share_participant_principal_id),
         {:ok, session_id} <- fetch_uuid(authorization, :share_participant_session_id),
         {:ok, capability_artifact} <-
           fetch_authorization_artifact(authorization, :share_capability_authorization),
         {:ok, participant_artifact} <-
           fetch_authorization_artifact(authorization, :share_participant_device_authorization),
         {:ok, capability_transcript} <- build_expected_capability_transcript(share),
         {:ok, participant_transcript} <-
           build_expected_participant_transcript(share, authorization, principal_id, session_id),
         :ok <-
           verify_artifact(
             capability_artifact,
             capability_transcript,
             share.authorization_public_key_material,
             "share_capability_authorization",
             :invalid_share_capability_authorization,
             %{share: share}
           ),
         :ok <-
           verify_artifact(
             participant_artifact,
             participant_transcript,
             authorization.hybrid_signing_public_key_material,
             "share_participant_device_authorization",
             :invalid_share_participant_device_authorization,
             %{
               share: share,
               participant: %{
                 principal_id: principal_id,
                 session_id: session_id
               }
             }
           ) do
      {:ok,
       Map.merge(authorization, %{
         principal_id: principal_id,
         session_id: session_id,
         share_capability_authorization_transcript: capability_transcript,
         participant_authorization_transcript: participant_transcript
       })}
    end
  end

  defp fetch_uuid(attrs, field) do
    value = dual_key_get(attrs, field)

    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, {:invalid_field, field}}
    end
  end

  defp fetch_authorization_artifact(attrs, field) do
    case dual_key_get(attrs, field) do
      artifact when is_map(artifact) -> {:ok, artifact}
      _ -> {:error, {:missing_field, field}}
    end
  end

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  defp build_expected_capability_transcript(%Share{} = share) do
    transcript =
      Signature.build_share_capability_authorization_transcript!(%{
        token_hash: share.token_hash,
        workspace_pin_bootstrap_hash: share.authenticated_workspace_pin_bootstrap_hash,
        share_id: share.id,
        scope_kind: share.scope,
        scope_id: share.document_id,
        permission: share.permission,
        password_protected: share.password_protected,
        created_event_hash: share.created_event_hash,
        latest_bootstrap_event_hash: share.latest_bootstrap_event_hash,
        capability_context_hash: share.capability_context_hash,
        share_capability_secret_commitment: share.share_capability_secret_commitment,
        password_capability_secret_commitment: share.password_capability_secret_commitment
      })

    {:ok, transcript}
  rescue
    ArgumentError -> {:error, :invalid_share_capability_authorization}
  end

  defp build_expected_participant_transcript(
         %Share{} = share,
         authorization,
         principal_id,
         session_id
       ) do
    transcript =
      Signature.build_share_participant_device_authorization_transcript!(%{
        share_id: share.id,
        share_session_id: session_id,
        share_participant_principal_id: principal_id,
        share_participant_device_id: authorization.device_id,
        participant_signing_key_id:
          Signature.compute_signing_key_id!(authorization.hybrid_signing_public_key_material),
        participant_encryption_key_id:
          HybridEncryptionMaterial.compute_key_id!(
            authorization.hybrid_encryption_public_key_material
          ),
        capability_context_hash: share.capability_context_hash,
        share_created_event_hash: share.created_event_hash,
        latest_bootstrap_event_hash: share.latest_bootstrap_event_hash,
        scope_kind: share.scope,
        scope_id: share.document_id,
        permission: share.permission
      })

    {:ok, transcript}
  rescue
    ArgumentError -> {:error, :invalid_share_participant_device_authorization}
  end

  defp verify_artifact(
         artifact,
         expected_transcript,
         public_key_material,
         signing_purpose,
         invalid_reason,
         semantic_context
       ) do
    signature = dual_key_get(artifact, :signature)
    provided_transcript = dual_key_get(artifact, :transcript)

    cond do
      not is_map(signature) ->
        {:error, invalid_reason}

      is_map(provided_transcript) and provided_transcript != expected_transcript ->
        {:error, invalid_reason}

      true ->
        case Signature.verify_hybrid_signature_result(
               signing_purpose,
               expected_transcript,
               signature,
               public_key_material,
               semantic_context
             ) do
          :ok -> :ok
          {:error, _reason} -> {:error, invalid_reason}
        end
    end
  end
end
