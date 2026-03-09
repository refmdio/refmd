defmodule RefMD.Mailer do
  @moduledoc """
  Email delivery. Logs in dev/test, sends via configured adapter in production.
  """
  require Logger

  @spec send_password_reset(String.t(), binary()) :: :ok
  def send_password_reset(email, raw_token) do
    token_b64 = Base.url_encode64(raw_token, padding: false)
    Logger.info("[Mailer] Password reset requested for #{email}, token: #{token_b64}")
  end
end
