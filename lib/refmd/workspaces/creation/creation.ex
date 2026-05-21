defmodule RefMD.Workspaces.Creation do
  @moduledoc false

  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, JCS, Signature}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Workspaces.{Workspace, WorkspaceMember, WorkspaceRole}

  @spec create_default_workspace(Ecto.UUID.t(), String.t()) ::
          {:ok, Workspace.t()} | {:error, term()}
  def create_default_workspace(user_id, name) do
    slug = generate_slug(name)

    Repo.transaction(fn ->
      workspace =
        insert_or_rollback(
          %Workspace{}
          |> Workspace.changeset(%{name: name, slug: slug, owner_id: user_id})
        )

      roles =
        for {base_role, role_name} <- default_roles() do
          insert_or_rollback(
            %WorkspaceRole{created_at: DateTime.utc_now()}
            |> WorkspaceRole.changeset(%{
              workspace_id: workspace.id,
              name: role_name,
              base_role: base_role,
              is_default: base_role == "editor"
            })
          )
        end

      owner_role = Enum.find(roles, &(&1.base_role == "owner"))

      insert_or_rollback(
        %WorkspaceMember{joined_at: DateTime.utc_now()}
        |> WorkspaceMember.changeset(%{
          workspace_id: workspace.id,
          user_id: user_id,
          role_id: owner_role.id,
          is_default: true,
          joined_at: DateTime.utc_now()
        })
      )

      workspace
    end)
  end

  @spec create_workspace(Ecto.UUID.t(), String.t(), map()) ::
          {:ok, Workspace.t()} | {:error, term()}
  def create_workspace(user_id, name, opts \\ %{}) do
    slug = generate_slug(name)
    workspace_id = Map.get(opts, :workspace_id) || Ecto.UUID.generate()
    owner_role_id = Map.get(opts, :workspace_owner_role_id) || Ecto.UUID.generate()

    attrs =
      %{name: name, slug: slug, owner_id: user_id}
      |> maybe_put(:description, opts[:description])
      |> maybe_put(:icon, opts[:icon])

    Repo.transaction(fn ->
      workspace =
        insert_or_rollback(
          %Workspace{id: workspace_id}
          |> Workspace.changeset(attrs)
        )

      roles =
        for {base_role, role_name} <- default_roles() do
          insert_or_rollback(
            %WorkspaceRole{created_at: DateTime.utc_now()}
            |> maybe_put_role_id(base_role, owner_role_id)
            |> WorkspaceRole.changeset(%{
              workspace_id: workspace.id,
              name: role_name,
              base_role: base_role,
              is_default: base_role == "editor"
            })
          )
        end

      owner_role = Enum.find(roles, &(&1.base_role == "owner"))

      insert_or_rollback(
        %WorkspaceMember{joined_at: DateTime.utc_now()}
        |> WorkspaceMember.changeset(%{
          workspace_id: workspace.id,
          user_id: user_id,
          role_id: owner_role.id,
          is_default: false,
          joined_at: DateTime.utc_now()
        })
      )

      insert_workspace_key_directory!(workspace.id, user_id, owner_role, opts)

      workspace
    end)
  end

  defp default_roles do
    [
      {"owner", "Owner"},
      {"admin", "Admin"},
      {"editor", "Editor"},
      {"viewer", "Viewer"},
      {"guest", "Guest"}
    ]
  end

  defp maybe_put_role_id(%WorkspaceRole{} = role, "owner", role_id) when is_binary(role_id),
    do: %{role | id: role_id}

  defp maybe_put_role_id(%WorkspaceRole{} = role, _base_role, _role_id), do: role

  defp insert_workspace_key_directory!(
         workspace_id,
         user_id,
         owner_role,
         %{
           creator_device_id: device_id,
           key_directory: %{
             workspace_events: events,
             workspace_checkpoint: checkpoint
           }
         }
       )
       when is_binary(device_id) and is_list(events) and is_map(checkpoint) do
    device = RefMD.Devices.get_device(device_id)

    with %{user_id: ^user_id, revoked_at: nil} <- device,
         :ok <-
           assert_workspace_key_directory_materials!(
             events,
             checkpoint,
             workspace_id,
             user_id,
             owner_role,
             device
           ) do
      Encryption.insert_initial_workspace_key_directory!(
        workspace_id,
        events,
        checkpoint,
        checkpoint_signer_kind: "device"
      )
    else
      _ -> Repo.rollback(:invalid_key_directory)
    end
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp insert_workspace_key_directory!(_, _, _, _), do: Repo.rollback(:missing_key_directory)

  defp assert_workspace_key_directory_materials!(
         [
           %{"payload" => %{"event_type" => "device_key_added", "body" => device_body}},
           %{
             "payload" => %{"event_type" => "identity_key_added", "body" => identity_signing_body}
           },
           %{
             "payload" => %{
               "event_type" => "identity_key_added",
               "body" => identity_encryption_body
             }
           },
           %{"payload" => %{"event_type" => "member_added", "body" => member_body}}
         ],
         %{"payload" => checkpoint_payload},
         workspace_id,
         user_id,
         owner_role,
         device
       ) do
    expected_device_body = %{
      "user_id" => user_id,
      "device_id" => device.id,
      "signing_key_id" => device.signing_key_id,
      "encryption_key_id" => device.encryption_key_id
    }

    expected_member_body = %{
      "workspace_id" => workspace_id,
      "user_id" => user_id,
      "role_id" => owner_role.id,
      "base_role" => "owner"
    }

    cond do
      device_body != expected_device_body ->
        {:error, :invalid_key_directory}

      not checkpoint_contains_identity_signing_material_hash?(
        checkpoint_payload,
        identity_signing_body["key_id"],
        identity_signing_body["key_material_hash"],
        user_id
      ) ->
        {:error, :invalid_key_directory}

      not checkpoint_contains_material_hash?(
        checkpoint_payload,
        "identity_keys",
        identity_encryption_body["key_id"],
        identity_encryption_body["key_material_hash"]
      ) ->
        {:error, :invalid_key_directory}

      member_body != expected_member_body ->
        {:error, :invalid_key_directory}

      not checkpoint_contains_material?(
        checkpoint_payload,
        "device_keys",
        device.hybrid_signing_public_key_material
      ) ->
        {:error, :invalid_key_directory}

      not checkpoint_contains_material?(
        checkpoint_payload,
        "device_keys",
        device.hybrid_encryption_public_key_material
      ) ->
        {:error, :invalid_key_directory}

      true ->
        :ok
    end
  end

  defp assert_workspace_key_directory_materials!(_, _, _, _, _, _),
    do: {:error, :invalid_key_directory}

  defp checkpoint_contains_identity_signing_material_hash?(
         checkpoint_payload,
         key_id,
         material_hash,
         user_id
       ) do
    with identity when not is_nil(identity) <-
           RefMD.Encryption.get_user_identity_public_key(user_id),
         true <- identity.signing_key_id == key_id,
         true <-
           Hash.blake3_base64url(
             JCS.canonical_bytes!(identity.hybrid_signing_public_key_material)
           ) ==
             material_hash do
      checkpoint_contains_material_hash?(
        checkpoint_payload,
        "identity_keys",
        key_id,
        material_hash
      )
    else
      _ -> false
    end
  end

  defp checkpoint_contains_material?(checkpoint_payload, key, material) do
    key_id = key_material_id!(material)

    checkpoint_payload
    |> Map.get(key, [])
    |> Enum.any?(fn
      %{"key_id" => ^key_id, "key_material" => ^material} -> true
      _ -> false
    end)
  end

  defp checkpoint_contains_material_hash?(checkpoint_payload, key, key_id, material_hash)
       when is_binary(key_id) and is_binary(material_hash) do
    checkpoint_payload
    |> Map.get(key, [])
    |> Enum.any?(fn
      %{"key_id" => ^key_id, "key_material" => material} ->
        Hash.blake3_base64url(JCS.canonical_bytes!(material)) == material_hash

      _ ->
        false
    end)
  end

  defp checkpoint_contains_material_hash?(_, _, _, _), do: false

  defp key_material_id!(%{"protocol" => "refmd.hybrid-signing-key-material"} = material),
    do: Signature.compute_signing_key_id!(material)

  defp key_material_id!(%{"protocol" => "refmd.hybrid-encryption-key-material"} = material),
    do: HybridEncryptionMaterial.compute_key_id!(material)

  defp key_material_id!(_), do: raise(ArgumentError, "key_material_protocol_invalid")

  defp insert_or_rollback(changeset) do
    case Repo.insert(changeset) do
      {:ok, record} -> record
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp generate_slug(name) do
    base =
      name
      |> String.downcase()
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")

    base = if base == "", do: "workspace", else: base

    suffix =
      :crypto.strong_rand_bytes(4)
      |> Base.url_encode64(padding: false)
      |> String.downcase()
      |> String.replace("_", "-")
      |> String.replace(~r/-+/, "-")
      |> String.trim("-")

    "#{base}-#{suffix}"
  end
end
