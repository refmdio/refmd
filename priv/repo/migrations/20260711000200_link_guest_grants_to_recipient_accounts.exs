defmodule RefMD.Repo.Migrations.LinkGuestGrantsToRecipientAccounts do
  use Ecto.Migration

  def change do
    alter table(:workspace_guest_grants) do
      add :linked_account_user_id, references(:users, type: :uuid, on_delete: :restrict)
    end

    create index(:workspace_guest_grants, [:linked_account_user_id])
  end
end
