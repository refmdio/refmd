defmodule RefMD.Workspaces.GuestInvitation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "guest_invitations" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :token_hash, :string
    field :token_prefix, :string
    field :scope_kind, :string
    field :scope_id, :binary_id
    field :permission, :string
    field :kek_version, :integer
    field :bootstrap_key_commitment, :string
    field :encrypted_bootstrap_package, :map
    field :bootstrap_package_hash, :string
    field :bootstrap_package_key_recipient_wrap, :map
    field :bootstrap_package_key_maintenance_wrap, :map
    field :bootstrap_suite_id, :string
    field :capability_context_hash, :string
    field :max_redemptions, :integer, default: 1
    field :redemption_count, :integer, default: 0
    field :invited_by, :binary_id
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
  end

  def changeset(invitation, attrs) do
    invitation
    |> cast(attrs, [
      :id,
      :workspace_id,
      :token_hash,
      :token_prefix,
      :scope_kind,
      :scope_id,
      :permission,
      :kek_version,
      :bootstrap_key_commitment,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :bootstrap_package_key_recipient_wrap,
      :bootstrap_package_key_maintenance_wrap,
      :bootstrap_suite_id,
      :capability_context_hash,
      :max_redemptions,
      :redemption_count,
      :invited_by,
      :expires_at,
      :revoked_at
    ])
    |> validate_required([
      :workspace_id,
      :token_hash,
      :token_prefix,
      :scope_kind,
      :permission,
      :kek_version,
      :bootstrap_key_commitment,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :bootstrap_package_key_recipient_wrap,
      :bootstrap_suite_id,
      :capability_context_hash,
      :max_redemptions,
      :redemption_count,
      :invited_by,
      :expires_at
    ])
    |> validate_inclusion(:scope_kind, ~w(workspace document folder share))
    |> validate_inclusion(:permission, ~w(view edit))
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:token_prefix, is: 4)
    |> validate_format(:token_prefix, ~r/^[A-Za-z0-9\-_]{4}$/)
    |> validate_length(:bootstrap_key_commitment, is: 43)
    |> validate_format(:bootstrap_key_commitment, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:bootstrap_package_hash, is: 43)
    |> validate_format(:bootstrap_package_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:capability_context_hash, is: 43)
    |> validate_format(:capability_context_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_number(:kek_version, greater_than: 0)
    |> validate_number(:max_redemptions, greater_than: 0)
    |> validate_number(:redemption_count, greater_than_or_equal_to: 0)
    |> validate_target_scope()
    |> unique_constraint(:token_hash)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:invited_by)
  end

  defp validate_target_scope(changeset) do
    scope = get_field(changeset, :scope_kind)
    scope_id = get_field(changeset, :scope_id)

    cond do
      scope == "workspace" and not is_nil(scope_id) ->
        add_error(changeset, :scope_id, "must be nil for workspace scope")

      scope in ["document", "folder", "share"] and is_nil(scope_id) ->
        add_error(changeset, :scope_id, "is required for document, folder, or share scope")

      true ->
        changeset
    end
  end
end
