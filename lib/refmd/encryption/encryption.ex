defmodule RefMD.Encryption do
  @moduledoc """
  The Encryption context. Manages E2EE key storage and distribution.
  """

  import Ecto.Query
  alias RefMD.Repo

  alias RefMD.Encryption.{
    UserIdentityPublicKey,
    UserEncryptedMasterKey,
    UserEncryptedIdentityKey,
    DeviceEncryptedUMK,
    WorkspaceEncryptedKey,
    DocumentEncryptedKey
  }
end
