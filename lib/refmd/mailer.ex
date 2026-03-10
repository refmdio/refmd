defmodule RefMD.Mailer do
  @moduledoc """
  Email delivery module using Swoosh.
  """

  use Swoosh.Mailer, otp_app: :refmd

  import Swoosh.Email

  @from_address {"RefMD", "noreply@refmd.io"}

  @spec send_password_reset(String.t(), binary()) :: {:ok, Swoosh.Email.t()} | {:error, any()}
  def send_password_reset(email, raw_token) do
    token_b64 = Base.url_encode64(raw_token, padding: false)
    base_url = RefMDWeb.Endpoint.url()
    reset_url = "#{base_url}/auth/password-reset?token=#{token_b64}"

    new()
    |> to(email)
    |> from(@from_address)
    |> subject("Password Reset — RefMD")
    |> text_body("""
    A password reset was requested for your RefMD account.

    Reset your password: #{reset_url}

    This link expires in 1 hour. If you did not request this, you can safely ignore this email.
    """)
    |> deliver()
  end
end
