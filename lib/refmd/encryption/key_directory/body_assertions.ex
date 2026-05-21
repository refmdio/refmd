defmodule RefMD.Encryption.KeyDirectory.BodyAssertions do
  @moduledoc false

  alias RefMD.Crypto.{Hash, Signature}

  @max_safe_integer 9_007_199_254_740_991

  @spec assert_exact_keys!(map(), [binary()]) :: :ok
  def assert_exact_keys!(map, expected_keys) when is_map(map) do
    if Enum.sort(Map.keys(map)) == expected_keys do
      :ok
    else
      raise ArgumentError, "keys_invalid"
    end
  end

  @spec assert_guest_scope!(term(), term()) :: :ok
  def assert_guest_scope!("workspace", "none"), do: :ok

  def assert_guest_scope!(scope_kind, scope_id)
      when scope_kind in ["document", "folder"] and is_binary(scope_id),
      do: :ok

  def assert_guest_scope!(_, _), do: raise(ArgumentError, "scope_invalid")

  @spec assert_permission!(term()) :: :ok
  def assert_permission!(permission) when permission in ["view", "edit"], do: :ok
  def assert_permission!(_), do: raise(ArgumentError, "permission_invalid")

  @spec assert_uuid!(term()) :: :ok
  def assert_uuid!(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, _} -> :ok
      :error -> raise(ArgumentError, "uuid_invalid")
    end
  end

  def assert_uuid!(_), do: raise(ArgumentError, "uuid_invalid")

  @spec assert_positive_integer!(term(), binary()) :: :ok
  def assert_positive_integer!(value, _error)
      when is_integer(value) and value > 0 and value <= @max_safe_integer,
      do: :ok

  def assert_positive_integer!(_, error), do: raise(ArgumentError, error)

  @spec assert_invitee_binding!(term()) :: :ok
  def assert_invitee_binding!(binding) when is_map(binding) do
    assert_exact_keys!(binding, Enum.sort(["email_hash", "kind"]))
    assert_literal!(binding["kind"], "email", "invitee_binding_kind_invalid")
    Hash.assert_blake3_base64url!(binding["email_hash"])
  end

  def assert_invitee_binding!(_), do: raise(ArgumentError, "invitee_binding_invalid")

  @spec assert_redeem_authority!(term()) :: :ok
  def assert_redeem_authority!(authority) when is_map(authority) do
    assert_exact_keys!(
      authority,
      Enum.sort(["hybrid_signing_public_key_material", "signer_kind", "signing_key_id"])
    )

    assert_literal!(
      authority["signer_kind"],
      "invitation_redeem_authority",
      "redeem_authority_kind_invalid"
    )

    Hash.assert_blake3_base64url!(authority["signing_key_id"])
    Signature.assert_public_key_material!(authority["hybrid_signing_public_key_material"])

    assert_literal!(
      authority["hybrid_signing_public_key_material"]["owner_kind"],
      "invitation_redeem_authority",
      "redeem_authority_owner_kind_invalid"
    )
  end

  def assert_redeem_authority!(_), do: raise(ArgumentError, "redeem_authority_invalid")

  @spec assert_invitation_bootstrap_update_common!(map()) :: :ok
  def assert_invitation_bootstrap_update_common!(body) do
    Hash.assert_blake3_base64url!(body["previous_bootstrap_package_hash"])
    Hash.assert_blake3_base64url!(body["bootstrap_package_hash"])
    Hash.assert_blake3_base64url!(body["bootstrap_package_key_maintenance_wrap_hash"])

    assert_positive_integer!(
      body["updated_at_event_sequence"],
      "updated_at_event_sequence_invalid"
    )
  end

  @spec assert_key_version_context!(term(), term(), term()) :: :ok
  def assert_key_version_context!(context, "workspace", "none") when is_map(context) do
    assert_exact_keys!(
      context,
      Enum.sort(["dek_version", "share_key_version", "workspace_kek_version"])
    )

    assert_positive_integer!(context["workspace_kek_version"], "kek_version_invalid")
    assert_literal!(context["share_key_version"], "NOT_APPLICABLE", "share_key_version_invalid")
    assert_literal!(context["dek_version"], "NOT_APPLICABLE", "dek_version_invalid")
  end

  def assert_key_version_context!(context, scope_kind, scope_id)
      when scope_kind in ["document", "folder", "share"] and is_binary(scope_id) and
             is_map(context) do
    assert_exact_keys!(
      context,
      Enum.sort(["dek_version", "share_key_version", "workspace_kek_version"])
    )

    assert_literal!(
      context["workspace_kek_version"],
      "NOT_APPLICABLE",
      "workspace_kek_version_invalid"
    )

    if scoped_key_version_valid?(context["share_key_version"], context["dek_version"]) do
      :ok
    else
      raise ArgumentError, "key_version_context_invalid"
    end
  end

  def assert_key_version_context!(_, _, _),
    do: raise(ArgumentError, "key_version_context_invalid")

  @spec assert_rotation_common!(map()) :: :ok
  def assert_rotation_common!(body) do
    assert_rotation_kind_scope!(body["rotation_kind"], body["scope_kind"])

    assert_positive_integer!(body["old_key_version"], "old_key_version_invalid")
    assert_positive_integer!(body["new_key_version"], "new_key_version_invalid")

    if body["new_key_version"] <= body["old_key_version"] do
      raise ArgumentError, "new_key_version_not_monotonic"
    else
      :ok
    end
  end

  @spec assert_rotation_kind_scope!(term(), term()) :: :ok
  def assert_rotation_kind_scope!("kek", "workspace"), do: :ok
  def assert_rotation_kind_scope!("dek", "document"), do: :ok
  def assert_rotation_kind_scope!("identity", "user"), do: :ok
  def assert_rotation_kind_scope!(_, _), do: raise(ArgumentError, "rotation_scope_invalid")

  @spec assert_literal!(term(), term(), binary()) :: :ok
  def assert_literal!(value, value, _error), do: :ok
  def assert_literal!(_, _, error), do: raise(ArgumentError, error)

  defp scoped_key_version_valid?(share_key_version, dek_version) do
    valid_optional_key_version?(share_key_version) and valid_optional_key_version?(dek_version) and
      (is_integer(share_key_version) or is_integer(dek_version))
  end

  defp valid_optional_key_version?("NOT_APPLICABLE"), do: true
  defp valid_optional_key_version?(version), do: is_integer(version) and version > 0
end
