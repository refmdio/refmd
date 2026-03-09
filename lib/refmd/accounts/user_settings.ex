defmodule RefMD.Accounts.UserSettings do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_settings" do
    belongs_to :user, RefMD.Accounts.User, primary_key: true
    field :theme, :string, default: "system"
    field :locale, :string, default: "en"
    field :editor_vim_mode, :boolean, default: false
    field :editor_font_size, :integer, default: 14

    field :updated_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(settings, attrs) do
    settings
    |> cast(attrs, [:theme, :locale, :editor_vim_mode, :editor_font_size])
    |> validate_required([:theme, :locale, :editor_vim_mode, :editor_font_size])
    |> validate_inclusion(:theme, ~w(light dark system))
  end
end
