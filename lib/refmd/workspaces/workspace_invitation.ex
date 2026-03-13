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
    field :encrypted_kek, :binary
    field :kek_nonce, :binary
    field :kek_version, :integer
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
      :encrypted_kek,
      :kek_nonce,
      :kek_version,
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
      :encrypted_kek,
      :kek_nonce,
      :kek_version,
      :expires_at,
      :created_at
    ])
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:token_prefix, is: 4)
    |> validate_format(:token_prefix, ~r/^[A-Za-z0-9\-_]{4}$/)
    |> validate_number(:kek_version, greater_than: 0)
    |> unique_constraint(:token_hash)
    |> unique_constraint(:id, name: :workspace_invitations_pkey)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:role_id, name: :workspace_invitations_role_fk)
  end
end
