defmodule RefMD.Users.UserSettings do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Plugins.NetworkProxyRegistration

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_settings" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :theme, :string, default: "system"
    field :locale, :string, default: "en"
    field :editor_vim_mode, :boolean, default: false
    field :editor_font_size, :integer, default: 14
    field :editor_default_mode, :string, default: "split"
    field :editor_layout_mode, :string, default: "tiling"
    field :plugin_network_proxy, :map

    field :updated_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(settings, attrs) do
    settings
    |> cast(attrs, [
      :theme,
      :locale,
      :editor_vim_mode,
      :editor_font_size,
      :editor_default_mode,
      :editor_layout_mode,
      :plugin_network_proxy
    ])
    |> normalize_plugin_network_proxy()
    |> reject_nil_changes([
      :theme,
      :locale,
      :editor_vim_mode,
      :editor_font_size,
      :editor_default_mode,
      :editor_layout_mode
    ])
    |> validate_inclusion(:theme, ~w(light dark system))
    |> validate_inclusion(:editor_default_mode, ~w(markdown wysiwyg split))
    |> validate_inclusion(:editor_layout_mode, ~w(tiling horizontal vertical))
  end

  defp normalize_plugin_network_proxy(changeset) do
    case fetch_change(changeset, :plugin_network_proxy) do
      {:ok, value} ->
        case NetworkProxyRegistration.normalize(value, "user") do
          {:ok, normalized} ->
            put_change(changeset, :plugin_network_proxy, normalized)

          {:error, _reason} ->
            add_error(changeset, :plugin_network_proxy, "is invalid")
        end

      :error ->
        changeset
    end
  end

  defp reject_nil_changes(changeset, fields) do
    Enum.reduce(fields, changeset, fn field, cs ->
      if Map.has_key?(cs.changes, field) and is_nil(Map.get(cs.changes, field)) do
        add_error(cs, field, "can't be null")
      else
        cs
      end
    end)
  end
end
