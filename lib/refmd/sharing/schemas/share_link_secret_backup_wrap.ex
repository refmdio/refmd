defmodule RefMD.Sharing.ShareLinkSecretBackupWrap do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_link_secret_backup_wraps" do
    belongs_to :share, RefMD.Sharing.Share

    field :recipient_user_id, :binary_id
    field :recipient_device_id, :binary_id
    field :recipient_encryption_key_id, :string
    field :wrap, :map

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :share_id,
      :recipient_user_id,
      :recipient_device_id,
      :recipient_encryption_key_id,
      :wrap
    ])
    |> validate_required([
      :share_id,
      :recipient_user_id,
      :recipient_device_id,
      :recipient_encryption_key_id,
      :wrap
    ])
    |> validate_length(:recipient_encryption_key_id, min: 1)
    |> unique_constraint([:share_id, :recipient_device_id],
      name: :share_link_secret_backup_wraps_share_device_index
    )
  end
end
