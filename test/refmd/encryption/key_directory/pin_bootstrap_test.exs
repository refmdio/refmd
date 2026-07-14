defmodule RefMD.Encryption.KeyDirectory.PinBootstrapTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.Signature
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory.Event
  alias RefMD.Encryption.KeyDirectory.PinBootstrap
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
  end

  setup do
    owner_id = create_user("pin-bootstrap-owner@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Pin Bootstrap Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)

    %{
      workspace: workspace,
      checkpoint: Encryption.current_workspace_key_directory_checkpoint(workspace.id),
      bootstrap: test_workspace_pin_bootstrap!(workspace.id)
    }
  end

  test "validate!/4 accepts a signed exact workspace pin bootstrap", %{
    workspace: workspace,
    checkpoint: checkpoint,
    bootstrap: bootstrap
  } do
    operation_sequence = get_in(bootstrap, ["payload", "event_head_sequence"])

    assert :ok = PinBootstrap.validate!(workspace.id, bootstrap, checkpoint, operation_sequence)
  end

  test "hash!/2 rejects recipient or resource fields in the static payload", %{
    workspace: workspace,
    bootstrap: bootstrap
  } do
    resource_bootstrap =
      update_in(bootstrap, ["payload"], &Map.put(&1, "resource_hash", "not-allowed"))

    recipient_bootstrap =
      update_in(bootstrap, ["payload", "issuer"], fn issuer ->
        Map.put(issuer, "recipient_device_id", Ecto.UUID.generate())
      end)

    assert_raise ArgumentError, "workspace_pin_payload_invalid", fn ->
      PinBootstrap.hash!(workspace.id, resource_bootstrap)
    end

    assert_raise ArgumentError, "workspace_pin_payload_invalid", fn ->
      PinBootstrap.hash!(workspace.id, recipient_bootstrap)
    end
  end

  test "validate!/4 rejects a signer user without authority at the bootstrap event head", %{
    workspace: workspace,
    checkpoint: checkpoint,
    bootstrap: bootstrap
  } do
    unauthorized_bootstrap =
      put_in(bootstrap, ["payload", "issuer", "user_id"], Ecto.UUID.generate())

    operation_sequence = get_in(bootstrap, ["payload", "event_head_sequence"])

    assert_raise ArgumentError, "workspace_pin_issuer_authority_invalid", fn ->
      PinBootstrap.validate!(workspace.id, unauthorized_bootstrap, checkpoint, operation_sequence)
    end
  end

  test "validate!/4 rejects issuer checkpoint fields that do not match the pinned checkpoint", %{
    workspace: workspace,
    checkpoint: checkpoint,
    bootstrap: bootstrap
  } do
    operation_sequence = get_in(bootstrap, ["payload", "event_head_sequence"])

    wrong_sequence =
      put_in(bootstrap, ["payload", "issuer", "key_checkpoint_sequence"], 999)

    wrong_hash =
      put_in(
        bootstrap,
        ["payload", "issuer", "key_checkpoint_hash"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      )

    assert_raise ArgumentError, "workspace_pin_checkpoint_mismatch", fn ->
      PinBootstrap.validate!(workspace.id, wrong_sequence, checkpoint, operation_sequence)
    end

    assert_raise ArgumentError, "workspace_pin_checkpoint_mismatch", fn ->
      PinBootstrap.validate!(workspace.id, wrong_hash, checkpoint, operation_sequence)
    end
  end

  test "security-vector mutations reject checkpoint and suite-policy substitution", %{
    workspace: workspace,
    checkpoint: checkpoint,
    bootstrap: bootstrap
  } do
    vectors =
      Path.expand(
        "../../../../native/refmd_crypto/testdata/refmd-signed-pq-wrap-v1.json",
        __DIR__
      )
      |> File.read!()
      |> Jason.decode!()
      |> Map.fetch!("negative")
      |> Enum.filter(&(&1["base"] == "workspace-pin-bootstrap-v1"))

    assert length(vectors) == 3

    for vector <- vectors do
      mutated = Enum.reduce(vector["operations"], bootstrap, &apply_vector_patch/2)
      operation_sequence = get_in(mutated, ["payload", "event_head_sequence"])

      assert_raise ArgumentError, vector["expected_error"], fn ->
        PinBootstrap.validate!(workspace.id, mutated, checkpoint, operation_sequence)
      end
    end
  end

  test "validate!/4 accepts an issuing event covered by the checkpoint head", %{
    workspace: workspace,
    checkpoint: checkpoint,
    bootstrap: bootstrap
  } do
    covered_event =
      Event
      |> where(
        [e],
        e.scope_kind == "workspace" and e.scope_id == ^workspace.id and
          e.sequence < ^get_in(bootstrap, ["payload", "event_head_sequence"])
      )
      |> order_by([e], asc: e.sequence)
      |> Repo.one!()

    ancestor_bootstrap =
      bootstrap
      |> put_in(["payload", "issuing_event_hash"], covered_event.event_hash)
      |> resign_bootstrap()

    operation_sequence = get_in(ancestor_bootstrap, ["payload", "event_head_sequence"])

    assert :ok =
             PinBootstrap.validate!(
               workspace.id,
               ancestor_bootstrap,
               checkpoint,
               operation_sequence
             )
  end

  test "hash!/2 rejects a non-canonical bootstrap nonce", %{
    workspace: workspace,
    bootstrap: bootstrap
  } do
    bad_nonce = put_in(bootstrap, ["payload", "bootstrap_nonce"], "abc")

    assert_raise ArgumentError, "workspace_pin_payload_invalid", fn ->
      PinBootstrap.hash!(workspace.id, bad_nonce)
    end
  end

  defp resign_bootstrap(%{"payload" => payload} = bootstrap) do
    issuer = Map.fetch!(payload, "issuer")
    device_id = Map.fetch!(issuer, "device_id")
    private_material = hybrid_signing_private_key_material("device", device_id)
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_workspace_pin_bootstrap_transcript!(
        device_id,
        Map.fetch!(payload, "workspace_id"),
        payload
      )

    put_in(
      bootstrap,
      ["signatures"],
      [
        %{
          "signer" => issuer,
          "signature" =>
            Signature.__test_sign_hybrid_signature__(
              "workspace_pin_bootstrap",
              transcript,
              private_material,
              public_material
            )
        }
      ]
    )
  end

  defp apply_vector_patch(%{"op" => "replace", "path" => path, "value" => value}, bootstrap) do
    keys = path |> String.split("/", trim: true) |> Enum.map(&Access.key!/1)
    put_in(bootstrap, keys, value)
  end
end
