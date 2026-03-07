defmodule Mix.Tasks.Openapi.Gen do
  @shortdoc "Generate OpenAPI JSON spec for frontend type generation"

  use Mix.Task

  @impl Mix.Task
  def run(_args) do
    Mix.Task.run("app.start")

    spec = RefMDWeb.ApiSpec.spec() |> Jason.encode!(pretty: true)
    path = Path.join(["assets", "openapi.json"])
    File.write!(path, spec)

    Mix.shell().info("OpenAPI spec written to #{path}")
  end
end
