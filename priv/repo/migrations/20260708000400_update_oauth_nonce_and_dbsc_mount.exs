defmodule RefMD.Repo.Migrations.UpdateOauthNonceAndDbscMount do
  use Ecto.Migration

  def up do
    execute("""
    ALTER TABLE oauth_states
    ADD COLUMN IF NOT EXISTS nonce text NOT NULL DEFAULT ''
    """)

    execute("""
    ALTER TABLE oauth_states
    ALTER COLUMN nonce DROP DEFAULT
    """)

    execute("""
    ALTER TABLE dbsc_session_bindings
    DROP CONSTRAINT IF EXISTS dbsc_session_kind_check
    """)

    create constraint(:dbsc_session_bindings, :dbsc_session_kind_check,
             check: "session_kind in ('user', 'share_participant', 'mount')"
           )
  end

  def down do
    execute("""
    ALTER TABLE dbsc_session_bindings
    DROP CONSTRAINT IF EXISTS dbsc_session_kind_check
    """)

    create constraint(:dbsc_session_bindings, :dbsc_session_kind_check,
             check: "session_kind in ('user', 'share_participant')"
           )

    execute("""
    ALTER TABLE oauth_states
    DROP COLUMN IF EXISTS nonce
    """)
  end
end
