defmodule RefMD.Repo.Migrations.AddInvitationRecipientDelivery do
  use Ecto.Migration

  def change do
    alter table(:workspace_invitations) do
      add :delivery_mode, :string, null: false, default: "unknown_fragment"
      add :recipient_user_id, references(:users, type: :uuid, on_delete: :restrict)
      add :recipient_device_ids, {:array, :uuid}, null: false, default: []
    end

    alter table(:guest_invitations) do
      add :invited_email, :string
      add :delivery_mode, :string, null: false, default: "unknown_fragment"
      add :recipient_user_id, references(:users, type: :uuid, on_delete: :restrict)
      add :recipient_device_ids, {:array, :uuid}, null: false, default: []
    end

    create index(:workspace_invitations, [:recipient_user_id])
    create index(:guest_invitations, [:recipient_user_id])

    create constraint(:workspace_invitations, :workspace_invitation_delivery_binding,
             check: delivery_binding_check()
           )

    create constraint(:guest_invitations, :guest_invitation_delivery_binding,
             check: delivery_binding_check()
           )
  end

  defp delivery_binding_check do
    """
    (delivery_mode = 'unknown_fragment' AND recipient_user_id IS NULL AND cardinality(recipient_device_ids) = 0)
    OR
    (delivery_mode = 'known_recipient' AND recipient_user_id IS NOT NULL AND cardinality(recipient_device_ids) > 0)
    """
  end
end
