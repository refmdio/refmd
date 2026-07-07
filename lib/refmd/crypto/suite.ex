defmodule RefMD.Crypto.Suite do
  @moduledoc false

  alias RefMD.Crypto.Hash
  alias RefMD.Crypto.JCS

  @signed_pq_hybrid_wrap "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @hybrid_signature "refmd-v2-hybrid-signature-ed25519-mldsa65"
  @initial_ake "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65"
  @initial_delivery "refmd-v2-initial-delivery-xchacha20poly1305"

  @protocol_version 1
  @suite_rank 1000
  @suite_policy_version 1
  @allowed_suite_ids Enum.sort([
                       @signed_pq_hybrid_wrap,
                       @hybrid_signature,
                       @initial_ake,
                       @initial_delivery
                     ])
  @required_components Enum.sort(["ed25519", "mldsa65", "mlkem768", "x25519"])

  def current_suite_policy do
    policy = %{
      "suite_policy_version" => @suite_policy_version,
      "min_suite_rank" => @suite_rank,
      "allowed_suite_ids" => @allowed_suite_ids,
      "required_components" => @required_components
    }

    Map.put(policy, "allowed_suite_ids_hash", canonical_allowed_suite_ids_hash(policy))
  end

  def assert_protocol_version!(@protocol_version), do: :ok
  def assert_protocol_version!(_), do: raise(ArgumentError, "protocol_version_not_allowed")

  def initial_ake_suite_id, do: @initial_ake

  def initial_delivery_suite_id, do: @initial_delivery

  def current_suite_rank, do: @suite_rank

  def assert_known_suite_id!(suite_id, policy \\ current_suite_policy()) do
    assert_suite_policy_shape!(policy)

    if suite_id in policy["allowed_suite_ids"] do
      :ok
    else
      raise ArgumentError, "suite_id_not_allowed"
    end
  end

  def assert_suite_rank_allowed!(suite_id, suite_rank, policy \\ current_suite_policy()) do
    assert_known_suite_id!(suite_id, policy)

    if suite_rank < policy["min_suite_rank"] or suite_rank != @suite_rank do
      raise ArgumentError, "suite_rank_not_allowed"
    end

    :ok
  end

  def assert_required_components!(%{"required_components" => components}) do
    assert_canonical_sorted_unique!(components, "required_components")

    if components == @required_components do
      :ok
    else
      raise ArgumentError, "required_components_mismatch"
    end
  end

  def canonical_allowed_suite_ids_hash(%{"allowed_suite_ids" => allowed_suite_ids}) do
    assert_canonical_sorted_unique!(allowed_suite_ids, "allowed_suite_ids")
    Hash.blake3_base64url(JCS.canonical_bytes!(%{"allowed_suite_ids" => allowed_suite_ids}))
  end

  def assert_pinned_suite_policy!(policy, pinned_policy) do
    assert_suite_policy_shape!(policy)

    cond do
      policy["suite_policy_version"] < pinned_policy["suite_policy_version"] ->
        raise ArgumentError, "suite_policy_version_rollback"

      policy["min_suite_rank"] < pinned_policy["min_suite_rank"] ->
        raise ArgumentError, "min_suite_rank_rollback"

      canonical_allowed_suite_ids_hash(policy) != pinned_policy["allowed_suite_ids_hash"] ->
        raise ArgumentError, "allowed_suite_ids_hash_mismatch"

      true ->
        :ok
    end
  end

  defp assert_suite_policy_shape!(policy) do
    assert_canonical_sorted_unique!(policy["allowed_suite_ids"], "allowed_suite_ids")

    hash = canonical_allowed_suite_ids_hash(policy)

    if Map.has_key?(policy, "allowed_suite_ids_hash") && policy["allowed_suite_ids_hash"] != hash do
      raise ArgumentError, "allowed_suite_ids_hash_mismatch"
    end

    if not Enum.all?(@allowed_suite_ids, &(&1 in policy["allowed_suite_ids"])) do
      raise ArgumentError, "allowed_suite_ids_incomplete"
    end

    if length(policy["allowed_suite_ids"]) != length(@allowed_suite_ids) do
      raise ArgumentError, "allowed_suite_ids_unknown"
    end

    assert_required_components!(policy)
  end

  defp assert_canonical_sorted_unique!(values, field) when is_list(values) do
    if Enum.uniq(values) != values do
      raise ArgumentError, "#{field}_duplicate"
    end

    if Enum.sort(values) != values do
      raise ArgumentError, "#{field}_not_canonical"
    end

    :ok
  end
end
