defmodule RefMD.Devices.Revocations.Authorization do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Devices.Revocations.{Intent, Prepare}
  alias RefMD.Security.CompoundAppend

  def verify!(pending, intent, command, authorization, device_id) do
    p = Prepare.validate!(pending.actor_user_id, pending.actor_device_id, device_id, command)
    CompoundAppend.validate_authorization!(authorization, intent)
    [scope] = intent["scopes"]
    [scope_signature] = authorization["scope_signatures"]
    verify_current_heads!(p, scope)
    verify_scope_signature!(p, scope, scope_signature)
    verify_effect_signatures!(p, scope, authorization["effect_authorizations"])

    %{
      prepared: p,
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
    literal!(entry["checkpoint_hash"], Audit.checkpoint_hash!("user_device", payload))

    transcript =
      Audit.build_audit_checkpoint_transcript!(
        "user_device",
        "device",
        p.actor_device_id,
        payload
      )

    verify_signature!(
      "audit_checkpoint",
      transcript,
      entry["signature"],
      p.actor_signing_material
    )
  end

  defp verify_effect_signatures!(p, scope, authorizations) do
    Enum.zip(scope["effect_signature_requirements"], authorizations)
    |> Enum.each(fn {requirement, authorization} ->
      {transcript, material} = effect_transcript(p, scope, requirement)
      literal!(requirement["subject_hash"], hash(transcript))

      verify_signature!(
        requirement["signing_purpose"],
        transcript,
        authorization["signature"],
        material
      )
    end)
  end

  defp effect_transcript(p, scope, %{"authorization_kind" => "key_directory_event"} = req) do
    effect = Enum.at(scope["candidate_key_directory_effects"], req["requirement_order"] - 1)
    payload = effect["event_payload"]

    {Signature.build_key_directory_event_transcript!(
       payload["event_type"],
       "identity",
       p.user_id,
       payload
     ), p.identity_signing_material}
  end

  defp effect_transcript(p, scope, %{"authorization_kind" => "key_directory_checkpoint"}) do
    signer = %{
      "signer_kind" => "identity",
      "user_id" => p.user_id,
      "signing_key_id" => p.identity_signing_key_id,
      "authorizing_checkpoint_sequence" => p.key_checkpoint.sequence,
      "authorizing_checkpoint_hash" => p.key_checkpoint.checkpoint_hash
    }

    {Signature.build_key_directory_checkpoint_transcript!(
       "identity_active",
       "identity",
       p.user_id,
       scope["candidate_key_directory_checkpoint_payload"],
       signer
     ), p.identity_signing_material}
  end

  defp effect_transcript(p, scope, %{"authorization_kind" => "device_revocation"}) do
    {Intent.revocation_transcript(p, List.last(scope["candidate_events"])),
     p.actor_signing_material}
  end

  defp verify_signature!(purpose, transcript, signature, material) do
    case Signature.verify_hybrid_signature_result(purpose, transcript, signature, material) do
      :ok -> :ok
      {:error, _} -> raise ArgumentError, "device_revocation_signature_invalid"
    end
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp literal!(value, value), do: :ok
  defp literal!(_, _), do: raise(ArgumentError, "device_revocation_binding_invalid")
end
