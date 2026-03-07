defmodule RefMDWeb.Router do
  use RefMDWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/api", RefMDWeb do
    pipe_through :api
  end
end
