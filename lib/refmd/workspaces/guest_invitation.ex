defmodule RefMD.Workspaces.GuestInvitation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "guest_invitations" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :token_hash, :string
    field :token_prefix, :string
    field :target_scope, :string
    belongs_to :target_document, RefMD.Documents.Document
    field :permission, :string
    field :encrypted_kek, :binary
    field :kek_nonce, :binary
    field :kek_version, :integer
    field :max_redemptions, :integer, default: 1
    field :redemption_count, :integer, default: 0
    field :invited_by, :binary_id
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
      :target_scope,
      :target_document_id,
      :permission,
      :encrypted_kek,
      :kek_nonce,
      :kek_version,
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
      :target_scope,
      :permission,
      :encrypted_kek,
      :kek_nonce,
      :kek_version,
      :max_redemptions,
      :redemption_count,
      :invited_by,
      :expires_at
    ])
    |> validate_inclusion(:target_scope, ~w(workspace document folder))
    |> validate_inclusion(:permission, ~w(view edit))
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:token_prefix, is: 4)
    |> validate_format(:token_prefix, ~r/^[A-Za-z0-9\-_]{4}$/)
    |> validate_number(:kek_version, greater_than: 0)
    |> validate_number(:max_redemptions, greater_than: 0)
    |> validate_number(:redemption_count, greater_than_or_equal_to: 0)
    |> validate_change(:encrypted_kek, fn field, value -> validate_byte_size(field, value, 48) end)
    |> validate_change(:kek_nonce, fn field, value -> validate_byte_size(field, value, 24) end)
    |> validate_target_scope()
    |> unique_constraint(:token_hash)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:target_document_id)
    |> foreign_key_constraint(:invited_by)
  end

  defp validate_target_scope(changeset) do
    scope = get_field(changeset, :target_scope)
    target_document_id = get_field(changeset, :target_document_id)

    cond do
      scope == "workspace" and not is_nil(target_document_id) ->
        add_error(changeset, :target_document_id, "must be nil for workspace scope")

      scope in ["document", "folder"] and is_nil(target_document_id) ->
        add_error(changeset, :target_document_id, "is required for document or folder scope")

      true ->
        changeset
    end
  end

  defp validate_byte_size(field, value, expected) when is_binary(value) do
    if byte_size(value) == expected,
      do: [],
      else: [{field, "must be exactly #{expected} bytes"}]
  end

  defp validate_byte_size(field, _value, _expected), do: [{field, "is invalid"}]
end
