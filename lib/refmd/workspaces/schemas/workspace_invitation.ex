defmodule RefMD.Workspaces.WorkspaceInvitation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "workspace_invitations" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :token_hash, :string
    field :token_prefix, :string
    field :role_id, :binary_id
    field :invited_by, :binary_id
    field :invited_email, :string
    field :kek_version, :integer
    field :bootstrap_key_commitment, :string
    field :encrypted_bootstrap_package, :map
    field :bootstrap_package_hash, :string
    field :bootstrap_package_key_recipient_wrap, :map
    field :bootstrap_package_key_maintenance_wrap, :map
    field :bootstrap_suite_id, :string
    field :capability_context_hash, :string
    field :is_used, :boolean, default: false
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(invitation, attrs) do
    invitation
    |> cast(attrs, [
      :id,
      :workspace_id,
      :token_hash,
      :token_prefix,
      :role_id,
      :invited_by,
      :invited_email,
      :kek_version,
      :bootstrap_key_commitment,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :bootstrap_package_key_recipient_wrap,
      :bootstrap_package_key_maintenance_wrap,
      :bootstrap_suite_id,
      :capability_context_hash,
      :is_used,
      :expires_at,
      :created_at,
      :revoked_at
    ])
    |> validate_required([
      :id,
      :workspace_id,
      :token_hash,
      :token_prefix,
      :invited_by,
      :invited_email,
      :kek_version,
      :bootstrap_key_commitment,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :bootstrap_package_key_recipient_wrap,
      :bootstrap_suite_id,
      :capability_context_hash,
      :expires_at,
      :created_at
    ])
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
    |> unique_constraint(:token_hash)
    |> unique_constraint(:id, name: :workspace_invitations_pkey)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:role_id, name: :workspace_invitations_role_fk)
  end
end
