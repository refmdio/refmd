defmodule RefMD.Encryption.KeyDirectory.DocumentAdmission do
  @moduledoc false

  alias RefMD.Crypto.{Encoding, Hash}
  alias RefMD.Encryption.KeyDirectory.BodyAssertions, as: A

  @spec assert!(binary(), map()) :: :ok
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
end
