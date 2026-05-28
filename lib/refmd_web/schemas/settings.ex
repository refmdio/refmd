defmodule RefMDWeb.Schemas.SettingsResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SettingsResponse",
    type: :object,
    properties: %{
      theme: %Schema{type: :string, enum: ["light", "dark", "system"]},
      locale: %Schema{type: :string},
      editor_vim_mode: %Schema{type: :boolean},
      editor_font_size: %Schema{type: :integer},
      editor_default_mode: %Schema{type: :string, enum: ["markdown", "wysiwyg", "split"]},
      editor_layout_mode: %Schema{type: :string, enum: ["tiling", "horizontal", "vertical"]},
      plugin_network_proxy: RefMDWeb.Schemas.PluginNetworkProxyRegistration
    },
    required: [
      :theme,
      :locale,
      :editor_vim_mode,
      :editor_font_size,
      :editor_default_mode,
      :editor_layout_mode
    ]
  })
end

defmodule RefMDWeb.Schemas.UpdateSettingsRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateSettingsRequest",
    type: :object,
    properties: %{
      theme: %Schema{type: :string, enum: ["light", "dark", "system"]},
      locale: %Schema{type: :string},
      editor_vim_mode: %Schema{type: :boolean},
      editor_font_size: %Schema{type: :integer},
      editor_default_mode: %Schema{type: :string, enum: ["markdown", "wysiwyg", "split"]},
      editor_layout_mode: %Schema{type: :string, enum: ["tiling", "horizontal", "vertical"]},
      plugin_network_proxy: RefMDWeb.Schemas.PluginNetworkProxyRegistration
    }
  })
end
