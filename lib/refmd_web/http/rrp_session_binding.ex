defmodule RefMDWeb.Http.RrpSessionBinding do
  @moduledoc false

  alias RefMD.Crypto.Hash

  def for_user_session(session) do
    %{
      "session_id_hash" => Hash.blake3_base64url(session.id),
      "session_kind" => "user",
      "is_recovery" => Map.get(session, :is_recovery, false) == true
    }
  end

  def for_share_session(session) do
    %{
      "session_id_hash" => Hash.blake3_base64url(session.id),
      "session_kind" => "share_participant",
      "share_id" => session.share_id,
      "is_recovery" => false
    }
  end
end
