defmodule RefMD.Encryption.KeyDirectory.DocumentAdmission do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash}
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  @max_write_session_lifetime_ms 60_000

  def assert!(type, body)
      when type in ["document_update_accepted", "document_snapshot_accepted"] do
    base_keys = [
      "actor_hash",
      "admission_nonce",
      "dek_version",
      "document_id",
      "document_permission_proof_hash",
      "event_type",
      "min_dek_version",
      "operation_hash",
      "operation_signature_hash",
      "previous_workspace_event_hash",
      "previous_workspace_event_sequence",
      "workspace_id"
    ]

    share_participant_keys = [
      "share_authority_kind",
      "share_id",
      "share_permission",
      "share_session_id"
    ]

    A.assert_exact_keys!(
      body,
      if(Map.has_key?(body, "share_id"),
        do: Enum.sort(base_keys ++ share_participant_keys),
        else: Enum.sort(base_keys)
      )
    )

    A.assert_literal!(body["event_type"], type, "event_body_type_mismatch")
    Hash.assert_blake3_base64url!(body["actor_hash"])
    Hash.assert_blake3_base64url!(body["document_permission_proof_hash"])
    Hash.assert_blake3_base64url!(body["operation_hash"])

    if Map.has_key?(body, "share_id") do
      A.assert_uuid!(body["share_id"])
      A.assert_uuid!(body["share_session_id"])
      A.assert_literal!(body["share_permission"], "edit", "share_permission_invalid")

      A.assert_literal!(
        body["share_authority_kind"],
        "share_participant_device",
        "share_authority_kind_invalid"
      )
    end

    Hash.assert_blake3_base64url!(body["operation_signature_hash"])
    Hash.assert_blake3_base64url!(body["previous_workspace_event_hash"])
    Encoding.decode_base64url!(body["admission_nonce"], 32)
    A.assert_positive_integer!(body["dek_version"], "dek_version_invalid")
    A.assert_positive_integer!(body["min_dek_version"], "min_dek_version_invalid")

    A.assert_positive_integer!(
      body["previous_workspace_event_sequence"],
      "previous_workspace_event_sequence_invalid"
    )
  end

  def assert!("document_write_session_admitted" = type, body) do
    base_keys = [
      "actor_hash",
      "authority_kind",
      "authority_scope_id",
      "document_id",
      "document_permission_proof_hash",
      "event_type",
      "expires_at_ms",
      "issued_at_ms",
      "max_ciphertext_bytes",
      "max_update_count",
      "min_dek_version",
      "previous_workspace_event_hash",
      "previous_workspace_event_sequence",
      "session_id",
      "session_nonce",
      "workspace_id"
    ]

    share_participant_keys = [
      "share_authority_kind",
      "share_id",
      "share_permission",
      "share_session_id"
    ]

    A.assert_exact_keys!(
      body,
      if(Map.has_key?(body, "share_id"),
        do: Enum.sort(base_keys ++ share_participant_keys),
        else: Enum.sort(base_keys)
      )
    )

    A.assert_literal!(body["event_type"], type, "event_body_type_mismatch")
    Hash.assert_blake3_base64url!(body["actor_hash"])
    Hash.assert_blake3_base64url!(body["document_permission_proof_hash"])
    Hash.assert_blake3_base64url!(body["previous_workspace_event_hash"])
    Encoding.decode_base64url!(body["session_id"], 32)
    Encoding.decode_base64url!(body["session_nonce"], 32)
    A.assert_positive_integer!(body["issued_at_ms"], "issued_at_ms_invalid")
    A.assert_positive_integer!(body["expires_at_ms"], "expires_at_ms_invalid")
    A.assert_positive_integer!(body["max_update_count"], "max_update_count_invalid")
    A.assert_positive_integer!(body["max_ciphertext_bytes"], "max_ciphertext_bytes_invalid")
    A.assert_positive_integer!(body["min_dek_version"], "min_dek_version_invalid")

    if body["expires_at_ms"] <= body["issued_at_ms"] or
         body["expires_at_ms"] - body["issued_at_ms"] > @max_write_session_lifetime_ms do
      raise ArgumentError, "expires_at_ms_invalid"
    end

    A.assert_positive_integer!(
      body["previous_workspace_event_sequence"],
      "previous_workspace_event_sequence_invalid"
    )

    if Map.has_key?(body, "share_id") do
      A.assert_uuid!(body["share_id"])
      A.assert_uuid!(body["share_session_id"])
      A.assert_literal!(body["share_permission"], "edit", "share_permission_invalid")

      A.assert_literal!(
        body["share_authority_kind"],
        "share_participant_device",
        "share_authority_kind_invalid"
      )
    end
  end

  def assert!("document_write_state_changed" = type, body) do
    A.assert_exact_keys!(
      body,
      Enum.sort([
        "document_id",
        "event_type",
        "issued_at_ms",
        "previous_workspace_event_hash",
        "previous_workspace_event_sequence",
        "previous_write_state",
        "reason",
        "workspace_id",
        "write_state"
      ])
    )

    A.assert_literal!(body["event_type"], type, "event_body_type_mismatch")
    A.assert_uuid!(body["workspace_id"])
    A.assert_uuid!(body["document_id"])
    Hash.assert_blake3_base64url!(body["previous_workspace_event_hash"])

    A.assert_positive_integer!(
      body["previous_workspace_event_sequence"],
      "previous_workspace_event_sequence_invalid"
    )

    A.assert_positive_integer!(body["issued_at_ms"], "issued_at_ms_invalid")
    assert_write_state!(body["previous_write_state"], "previous_write_state_invalid")
    assert_write_state!(body["write_state"], "write_state_invalid")
    assert_reason!(body["reason"])

    if body["previous_write_state"] == body["write_state"] do
      raise ArgumentError, "write_state_unchanged"
    end
  end

  defp assert_write_state!(state, _error)
       when state in ["writable", "read_only", "archived", "write_disabled"],
       do: :ok

  defp assert_write_state!(_state, error), do: raise(ArgumentError, error)

  defp assert_reason!(reason)
       when reason in [
              "archive",
              "unarchive",
              "read_only_enabled",
              "read_only_disabled",
              "policy"
            ],
       do: :ok

  defp assert_reason!(_reason), do: raise(ArgumentError, "write_state_reason_invalid")
end
