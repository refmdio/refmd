defmodule RefMD.Sharing.ShareOpenConsumption do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_open_consumptions" do
    belongs_to :share, RefMD.Sharing.Share

    field :consumer_kind, :string
    field :consumer_id, :binary_id
    field :consumed_at, :utc_datetime_usec
  end

  def changeset(consumption, attrs) do
    consumption
    |> cast(attrs, [:share_id, :consumer_kind, :consumer_id, :consumed_at])
    |> validate_required([:share_id, :consumer_kind, :consumer_id, :consumed_at])
    |> validate_inclusion(:consumer_kind, ~w(share_participant_device share_mount_user))
    |> unique_constraint([:share_id, :consumer_kind, :consumer_id],
      name: :share_open_consumptions_share_consumer_index
    )
    |> foreign_key_constraint(:share_id)
  end
end
