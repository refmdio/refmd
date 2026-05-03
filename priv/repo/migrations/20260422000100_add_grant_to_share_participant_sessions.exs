defmodule RefMD.Repo.Migrations.AddGrantToShareParticipantSessions do
  use Ecto.Migration

  def up do
    alter table(:share_participant_sessions) do
      add :grant, :string
    end

    execute("""
    UPDATE share_participant_sessions s
    SET "grant" = shares.permission
    FROM shares
    WHERE shares.id = s.share_id
    """)

    execute("""
    ALTER TABLE share_participant_sessions
    ALTER COLUMN "grant" SET NOT NULL
    """)

    execute(
      "ALTER TABLE share_participant_sessions ADD CONSTRAINT share_participant_sessions_grant_check CHECK (\"grant\" IN ('view', 'edit'))",
      "ALTER TABLE share_participant_sessions DROP CONSTRAINT share_participant_sessions_grant_check"
    )
  end

  def down do
    execute(
      "ALTER TABLE share_participant_sessions DROP CONSTRAINT IF EXISTS share_participant_sessions_grant_check"
    )

    alter table(:share_participant_sessions) do
      remove :grant
    end
  end
end
