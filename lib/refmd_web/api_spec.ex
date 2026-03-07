defmodule RefMDWeb.ApiSpec do
  alias OpenApiSpex.{Info, OpenApi, Paths, Server}

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "RefMD API",
        version: "1.0.0"
      },
      servers: [
        %Server{url: "/"}
      ],
      paths: Paths.from_router(RefMDWeb.Router)
    }
    |> OpenApiSpex.resolve_schema_modules()
  end
end
