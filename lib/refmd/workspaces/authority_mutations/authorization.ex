defmodule RefMD.Workspaces.AuthorityMutations.Authorization do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Security.CompoundAppend
  alias RefMD.Workspaces.AuthorityMutations.{Intent, Prepare}

  def verify!(pending, intent, command, authorization) do
    prepared =
      Prepare.validate!(
        pending.actor_user_id,
        pending.actor_device_id,
        pending.mutation_kind,
        command
      )

    CompoundAppend.validate_authorization!(authorization, intent)
    [scope] = intent["scopes"]
    [scope_signature] = authorization["scope_signatures"]
    verify_current_heads!(prepared, scope)
    verify_scope_signature!(prepared, scope, scope_signature)
    verify_effect_signatures!(prepared, scope, authorization["effect_authorizations"])

    %{
      prepared: prepared,
      scope: scope,
      scope_signature: scope_signature,
      effect_authorizations: authorization["effect_authorizations"]
    }
  end

  defp verify_current_heads!(p, scope) do
    literal!(scope["current_event_head"], %{
      "sequence" => p.audit_head.sequence,
      "event_hash" => p.audit_head.event_hash
    })

    literal!(
      scope["candidate_key_directory_checkpoint_payload"]["previous_checkpoint_hash"],
      p.key_checkpoint.checkpoint_hash
    )

    literal!(scope["previous_signed_checkpoint"], %{
      "sequence" => p.previous_signed_audit_checkpoint["payload"]["sequence"],
      "checkpoint_hash" => p.previous_signed_audit_checkpoint["checkpoint_hash"]
    })
  end

  defp verify_scope_signature!(p, scope, entry) do
    event = List.last(scope["candidate_events"])
    payload = Intent.audit_checkpoint_payload(p, event)
    literal!(entry["checkpoint_hash"], Audit.checkpoint_hash!("workspace_device", payload))

    transcript =
      Audit.build_audit_checkpoint_transcript!(
        "workspace_device",
        "device",
        p.actor_device_id,
        payload
      )

    literal!(entry["signature"]["transcript_hash"], hash(transcript))

    verify_signature!("audit_checkpoint", transcript, entry["signature"], p)
  end

  defp verify_effect_signatures!(p, scope, authorizations) do
    Enum.zip(scope["effect_signature_requirements"], authorizations)
    |> Enum.each(fn {requirement, authorization} ->
      transcript = effect_transcript(p, scope, requirement)
      literal!(requirement["subject_hash"], hash(transcript))
      verify_signature!(requirement["signing_purpose"], transcript, authorization["signature"], p)
    end)
  end

  defp effect_transcript(p, scope, %{"authorization_kind" => "key_directory_event"} = req) do
    payload =
      scope["candidate_key_directory_effects"]
      |> Enum.at(req["requirement_order"] - 1)
      |> Map.fetch!("event_payload")

    Signature.build_key_directory_event_transcript!(
      payload["event_type"],
      "device",
      p.actor_device_id,
      payload
    )
  end

  defp effect_transcript(p, scope, %{"authorization_kind" => "key_directory_checkpoint"}) do
    Signature.build_key_directory_checkpoint_transcript!(
      "workspace_authorized",
      "device",
      p.actor_device_id,
      scope["candidate_key_directory_checkpoint_payload"],
      Intent.checkpoint_signer(p)
    )
  end

  defp effect_transcript(p, scope, %{"authorization_kind" => "pq_wrap"} = req) do
    {wrap, effect_index} =
      case req["precommit_kind"] do
        "device_wrap" ->
          {Enum.at(p.business.device_wraps, req["precommit_index"]), 1 + req["precommit_index"]}

        "member_envelope" ->
          {Enum.at(p.business.member_envelopes, req["precommit_index"]),
           1 + length(p.business.device_wraps) + req["precommit_index"]}
      end

    effect = Enum.at(scope["candidate_key_directory_effects"], effect_index)
    checkpoint = scope["candidate_key_directory_checkpoint_payload"]
    covered = checkpoint["covered_event_head"]

    Signature.build_pq_wrap_transcript!(
      p.actor_device_id,
      wrap.wrap["sender"],
      %{
        "scope_kind" => "workspace",
        "scope_id" => p.workspace_id,
        "event_hash" => effect["event_hash"],
        "operation_checkpoint_sequence" => checkpoint["sequence"],
        "operation_checkpoint_hash" => scope["candidate_key_directory_checkpoint_hash"],
        "covered_event_head_sequence" => covered["head_sequence"],
        "covered_event_head_hash" => covered["head_hash"]
      },
      %{
        "resource_hash" => wrap.resource_hash,
        "wrap_body_hash" => wrap.wrap_body_hash,
        "wrap_event_body_hash" => hash(effect["event_payload"]["body"]),
        "wrap_event_hash" => effect["event_hash"],
        "hpke_info_hash" => wrap.hpke_info_hash,
        "aad_hash" => wrap.aad_hash
      }
    )
  end

  defp verify_signature!(purpose, transcript, signature, p) do
    case Signature.verify_hybrid_signature_result(
           purpose,
           transcript,
           signature,
           p.actor_signing_material
         ) do
      :ok ->
        :ok

      {:error, _} ->
        raise ArgumentError, "workspace_authority_mutation_#{purpose}_signature_invalid"
    end
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp literal!(value, value), do: :ok
  defp literal!(_, _), do: raise(ArgumentError, "workspace_authority_mutation_binding_invalid")
end
