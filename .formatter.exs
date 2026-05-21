[
  import_deps: [:ecto, :ecto_sql, :phoenix],
  subdirectories: ["priv/*/migrations"],
  inputs: ["*.{ex,exs}", ".credo/**/*.ex", "{config,lib,test}/**/*.{ex,exs}", "priv/*/seeds.exs"]
]
