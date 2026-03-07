defmodule RefMD.Repo do
  use Ecto.Repo,
    otp_app: :refmd,
    adapter: Ecto.Adapters.Postgres
end
