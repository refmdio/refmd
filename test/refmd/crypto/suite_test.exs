defmodule RefMD.Crypto.SuiteTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.Suite

  describe "suite admission" do
    test "validates current suite policy and pinned allowed-suite hash" do
      policy = Suite.current_suite_policy()
      assert policy["allowed_suite_ids_hash"] == "OcQ3VH6UrkTrIXcahgjG7weNblUpExxAM0rB5KqOVts"
      assert Suite.canonical_allowed_suite_ids_hash(policy) == policy["allowed_suite_ids_hash"]
      assert :ok = Suite.assert_protocol_version!(1)

      assert :ok =
               Suite.assert_known_suite_id!(
                 "refmd-v2-initial-ake-mlkem768-x25519-hkdfsha256-ed25519-mldsa65",
                 policy
               )

      assert :ok =
               Suite.assert_suite_rank_allowed!(
                 "refmd-v2-hybrid-signature-ed25519-mldsa65",
                 1000,
                 policy
               )

      assert :ok = Suite.assert_required_components!(policy)

      assert :ok =
               Suite.assert_pinned_suite_policy!(policy, %{
                 "suite_policy_version" => 1,
                 "min_suite_rank" => 1000,
                 "allowed_suite_ids_hash" => policy["allowed_suite_ids_hash"]
               })
    end

    test "rejects protocol and suite downgrades" do
      policy = Suite.current_suite_policy()

      assert_raise ArgumentError, fn -> Suite.assert_protocol_version!(0) end
      assert_raise ArgumentError, fn -> Suite.assert_protocol_version!(2) end

      assert_raise ArgumentError, fn ->
        Suite.assert_known_suite_id!("refmd-v1-static-dh", policy)
      end

      assert_raise ArgumentError, fn ->
        Suite.assert_suite_rank_allowed!("refmd-v2-hybrid-signature-ed25519-mldsa65", 999, policy)
      end

      assert_raise ArgumentError, fn ->
        Suite.assert_pinned_suite_policy!(
          %{policy | "allowed_suite_ids" => tl(policy["allowed_suite_ids"])},
          %{
            "suite_policy_version" => 1,
            "min_suite_rank" => 1000,
            "allowed_suite_ids_hash" => policy["allowed_suite_ids_hash"]
          }
        )
      end

      assert_raise ArgumentError, fn ->
        Suite.assert_known_suite_id!(
          "refmd-v2-unknown-extra",
          %{
            policy
            | "allowed_suite_ids" =>
                Enum.sort(policy["allowed_suite_ids"] ++ ["refmd-v2-unknown-extra"])
          }
        )
      end

      assert_raise ArgumentError, fn ->
        Suite.assert_required_components!(%{
          policy
          | "required_components" => ["ed25519", "mldsa65"]
        })
      end
    end
  end
end
