defmodule RefMD.Workspaces.Genesis.Authorization do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Security.CompoundAppend
  alias RefMD.Workspaces.Genesis.Prepare

  def verify!(pending, intent, command, authorization) do
    prepared = Prepare.validate!(pending.actor_user_id, pending.actor_device_id, command)
    CompoundAppend.validate_authorization!(authorization, intent)
    [scope] = intent["scopes"]
    [scope_signature] = authorization["scope_signatures"]
    verify_scope_signature!(prepared, scope, scope_signature)
    verify_effect_signatures!(prepared, scope, authorization["effect_authorizations"])

    %{
      prepared: prepared,
      intent: intent,
      command: command,
      authorization: authorization,
      scope: scope,
      scope_signature: scope_signature,
      effect_authorizations: authorization["effect_authorizations"]
    }
  end

  defp verify_scope_signature!(p, scope, entry) do
    payload = audit_checkpoint_payload(p, List.last(scope["candidate_events"]))
    literal!(entry["checkpoint_hash"], Audit.checkpoint_hash!("workspace_device", payload))

    transcript =
      Audit.build_audit_checkpoint_transcript!(
        "workspace_device",
        "device",
        p.device_id,
        payload
      )

    verify_signature!(
      "audit_checkpoint",
      transcript,
      entry["signature"],
      p.device_signing_material
    )
  end

  defp verify_effect_signatures!(p, scope, authorizations) do
    Enum.zip(scope["effect_signature_requirements"], authorizations)
    |> Enum.each(fn {requirement, authorization} ->
      transcript = effect_transcript!(p, scope, requirement)
      literal!(requirement["subject_hash"], hash(transcript))

      verify_signature!(
        requirement["signing_purpose"],
        transcript,
        authorization["signature"],
        p.device_signing_material
      )
    end)
  end

  defp effect_transcript!(p, scope, %{"authorization_kind" => "key_directory_event"} = req) do
    effect = Enum.at(scope["candidate_key_directory_effects"], req["requirement_order"] - 1)
    payload = effect["event_payload"]
    literal!(effect["event_hash"], KeyDirectory.event_hash(payload))

    Signature.build_key_directory_event_transcript!(
      payload["event_type"],
      "device",
      p.device_id,
      payload
    )
  end

  defp effect_transcript!(p, scope, %{"authorization_kind" => "key_directory_checkpoint"}) do
    signer = %{
      "signer_kind" => "device",
      "user_id" => p.user_id,
      "device_id" => p.device_id,
      "signing_key_id" => p.device_signing_key_id,
      "authorizing_checkpoint_sequence" => 0,
      "authorizing_checkpoint_hash" => "GENESIS"
    }

    Signature.build_key_directory_checkpoint_transcript!(
      "workspace_initial",
      "device",
      p.device_id,
      scope["candidate_key_directory_checkpoint_payload"],
      signer
    )
  end

  defp effect_transcript!(p, scope, %{"authorization_kind" => "pq_wrap"}) do
    event = List.last(scope["candidate_key_directory_effects"])["event_payload"]
    event_hash = KeyDirectory.event_hash(event)
    member = p.member_envelope
    sender = p.command["workspace_member_envelope_precommit"]["wrap"]["sender"]

    Signature.build_pq_wrap_transcript!(
      p.device_id,
      sender,
      %{
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "event_hash" => event_hash,
        "operation_checkpoint_sequence" => 1,
        "operation_checkpoint_hash" => scope["candidate_key_directory_checkpoint_hash"],
        "covered_event_head_sequence" => event["sequence"],
        "covered_event_head_hash" => event_hash
      },
      %{
        "resource_hash" => member.resource_hash,
        "wrap_body_hash" => member.wrap_body_hash,
        "wrap_event_body_hash" => hash(event["body"]),
        "wrap_event_hash" => event_hash,
        "hpke_info_hash" => member.hpke_info_hash,
        "aad_hash" => member.aad_hash
      },
      "workspace_genesis"
    )
  end

  defp audit_checkpoint_payload(p, event) do
    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => p.workspace_id,
      "sequence" => event["sequence"],
      "event_hash" => event["event_hash"],
      "signer_user_id" => p.user_id,
      "signer_device_id" => p.device_id,
      "signing_key_id" => p.device_signing_key_id,
      "authorization_checkpoint_scope_kind" => "workspace",
      "authorization_checkpoint_scope_id" => p.workspace_id,
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => "workspace.genesis"
    }
  end

  defp verify_signature!(purpose, transcript, signature, material) do
    case Signature.verify_hybrid_signature_result(purpose, transcript, signature, material) do
      :ok -> :ok
      {:error, _} -> raise ArgumentError, "workspace_genesis_signature_invalid"
    end
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp literal!(actual, expected) when actual == expected, do: :ok
  defp literal!(_, _), do: raise(ArgumentError, "workspace_genesis_binding_invalid")
end
