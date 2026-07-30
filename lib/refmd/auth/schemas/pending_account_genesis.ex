defmodule RefMD.Auth.PendingAccountGenesis do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:registration_id, :binary_id, autogenerate: false}

  schema "pending_account_geneses" do
    field :reserved_user_id, :binary_id
    field :reserved_workspace_id, :binary_id
    field :reserved_workspace_role_ids, :map
    field :normalized_email, :string
    field :display_name, :string
    field :credential, :map
    field :expires_at, :utc_datetime_usec
    field :consumed_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(genesis, attrs) do
    genesis
    |> cast(attrs, [
      :registration_id,
      :reserved_user_id,
      :reserved_workspace_id,
      :reserved_workspace_role_ids,
      :normalized_email,
      :display_name,
      :credential,
      :expires_at,
      :consumed_at,
      :created_at
    ])
    |> validate_required([
      :registration_id,
      :reserved_user_id,
      :reserved_workspace_id,
      :reserved_workspace_role_ids,
      :normalized_email,
      :display_name,
      :credential,
      :expires_at,
      :created_at
    ])
    |> validate_role_ids()
    |> validate_credential()
    |> unique_constraint(:reserved_user_id)
    |> unique_constraint(:reserved_workspace_id)
    |> unique_constraint(:normalized_email)
  end

  defp validate_role_ids(changeset) do
    case get_field(changeset, :reserved_workspace_role_ids) do
      %{"owner" => owner, "admin" => admin, "editor" => editor, "viewer" => viewer} = ids
      when map_size(ids) == 4 ->
        if Enum.all?([owner, admin, editor, viewer], &valid_uuid?/1),
          do: changeset,
          else: add_error(changeset, :reserved_workspace_role_ids, "is invalid")

      _ ->
        add_error(changeset, :reserved_workspace_role_ids, "is invalid")
    end
  end

  defp validate_credential(changeset) do
    if valid_credential?(get_field(changeset, :credential)),
      do: changeset,
      else: add_error(changeset, :credential, "is invalid")
  end

  defp valid_credential?(
         %{
           "kind" => "password",
           "auth_key_verifier" => verifier,
           "salt_b64u" => salt,
           "kdf_type" => "argon2id",
           "kdf_params" => params
         } = credential
       ) do
    map_size(credential) == 5 and is_binary(verifier) and is_binary(salt) and is_map(params)
  end

  defp valid_credential?(
         %{
           "kind" => "oauth",
           "provider" => provider,
           "provider_user_id" => provider_user_id,
           "verified_email" => verified_email
         } = credential
       ) do
    map_size(credential) == 4 and is_binary(provider) and is_binary(provider_user_id) and
      is_binary(verified_email)
  end

  defp valid_credential?(_), do: false

  defp valid_uuid?(value) when is_binary(value), do: match?({:ok, _}, Ecto.UUID.cast(value))
  defp valid_uuid?(_), do: false
end
