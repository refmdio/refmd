defmodule RefMD.Crypto.SigningSurface do
  @moduledoc false

  @protocol_version 1
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"

  @owner_identity ["identity"]
  @owner_device ["device"]
  @owner_key_directory_event ["identity", "device"]
  @owner_key_directory_invitation_redeem_event ["device", "invitation_redeem_authority"]
  @owner_key_directory_document_event ["device", "share_participant_device"]
  @owner_share_participant_device ["share_participant_device"]
  @owner_share_capability ["share_capability"]
  @owner_invitation_redeem_authority ["invitation_redeem_authority"]

  @key_directory_event_variants [
    "wrap_issued",
    "identity_key_added",
    "device_key_added",
    "member_added",
    "member_role_changed",
    "member_removed",
    "signing_key_revoked",
    "encryption_key_revoked",
    "suite_policy_changed",
    "share_created",
    "share_metadata_updated",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_exclusion_changed",
    "share_revoked",
    "recipient_bound_delivery_admitted",
    "workspace_invitation_created",
    "workspace_invitation_bootstrap_updated",
    "workspace_invitation_revoked",
    "workspace_invitation_redeemed",
    "guest_invitation_created",
    "guest_invitation_bootstrap_updated",
    "guest_invitation_revoked",
    "guest_invitation_redeemed",
    "guest_grant_revoked",
    "guest_device_revoked",
    "rotation_started",
    "rotation_completed",
    "old_key_deleted",
    "document_write_session_admitted",
    "document_write_state_changed",
    "document_snapshot_accepted"
  ]
  @rrp_request_variants [
    "http_user_device",
    "http_share_participant_device",
    "channel_user_device",
    "channel_share_participant_device"
  ]

  defp static_surfaces do
    [
      surface("pq_wrap", "pq_wrap", "refmd.wrap.pq_wrap", "none", @owner_device),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.identity_initial",
        "identity_initial",
        @owner_identity
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.workspace_initial",
        "workspace_initial",
        @owner_device
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.identity_active",
        "identity_active",
        @owner_identity
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.identity_rotation",
        "identity_rotation",
        @owner_identity
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.workspace_authorized",
        "workspace_authorized",
        @owner_device
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.invitation_redeem_authority",
        "invitation_redeem_authority",
        @owner_invitation_redeem_authority
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.share_participant_document_operation",
        "share_participant_document_operation",
        @owner_share_participant_device
      ),
      surface(
        "key_directory_checkpoint",
        "key_directory_checkpoint",
        "refmd.key_directory.checkpoint.device_authorized",
        "device_authorized",
        @owner_device
      ),
      surface(
        "workspace_pin_bootstrap",
        "workspace_pin_bootstrap",
        "refmd.workspace.pin_bootstrap",
        "none",
        @owner_device
      ),
      key_directory_event_surface("wrap_issued"),
      key_directory_event_surface("identity_key_added"),
      key_directory_event_surface("device_key_added"),
      key_directory_event_surface("member_added"),
      key_directory_event_surface("member_role_changed"),
      key_directory_event_surface("member_removed"),
      key_directory_event_surface("signing_key_revoked"),
      key_directory_event_surface("encryption_key_revoked"),
      key_directory_event_surface("suite_policy_changed"),
      key_directory_event_surface("share_created"),
      key_directory_event_surface("share_metadata_updated"),
      key_directory_event_surface("share_key_scope_added"),
      key_directory_event_surface("share_key_scope_replaced"),
      key_directory_event_surface("share_key_scope_removed"),
      key_directory_event_surface("share_exclusion_changed"),
      key_directory_event_surface("share_revoked"),
      key_directory_event_surface("recipient_bound_delivery_admitted"),
      key_directory_event_surface("workspace_invitation_created"),
      key_directory_event_surface("workspace_invitation_bootstrap_updated"),
      key_directory_event_surface("workspace_invitation_revoked"),
      key_directory_event_surface("workspace_invitation_redeemed"),
      key_directory_event_surface("guest_invitation_created"),
      key_directory_event_surface("guest_invitation_bootstrap_updated"),
      key_directory_event_surface("guest_invitation_revoked"),
      key_directory_event_surface("guest_invitation_redeemed"),
      key_directory_event_surface("guest_grant_revoked"),
      key_directory_event_surface("guest_device_revoked"),
      key_directory_event_surface("rotation_started"),
      key_directory_event_surface("rotation_completed"),
      key_directory_event_surface("old_key_deleted"),
      key_directory_event_surface("document_write_session_admitted"),
      key_directory_event_surface("document_write_state_changed"),
      key_directory_event_surface("document_snapshot_accepted"),
      surface(
        "recipient_bound_authorization",
        "recipient_bound_authorization",
        "refmd.recipient_bound.authorization",
        "none",
        @owner_device
      ),
      surface(
        "share_capability_authorization",
        "share_capability_authorization",
        "refmd.share.capability_authorization",
        "none",
        @owner_share_capability
      ),
      surface(
        "share_participant_device_authorization",
        "share_participant_device_authorization",
        "refmd.share.participant_device_authorization",
        "none",
        @owner_share_participant_device
      ),
      surface(
        "rrp_request",
        "rrp_request",
        "refmd.rrp.request.http_user_device",
        "http_user_device",
        @owner_device
      ),
      surface(
        "rrp_request",
        "rrp_request",
        "refmd.rrp.request.http_share_participant_device",
        "http_share_participant_device",
        @owner_share_participant_device
      ),
      surface(
        "rrp_request",
        "rrp_request",
        "refmd.rrp.request.channel_user_device",
        "channel_user_device",
        @owner_device
      ),
      surface(
        "rrp_request",
        "rrp_request",
        "refmd.rrp.request.channel_share_participant_device",
        "channel_share_participant_device",
        @owner_share_participant_device
      ),
      surface(
        "genesis_device_bootstrap",
        "genesis_device_bootstrap",
        "refmd.device.genesis_device_bootstrap",
        "none",
        @owner_identity
      ),
      surface(
        "device_approval",
        "device_approval",
        "refmd.device.approval",
        "none",
        @owner_device
      ),
      surface(
        "plugin_bundle_approval",
        "plugin_bundle_approval",
        "refmd.plugin.bundle_approval",
        "none",
        @owner_device
      ),
      surface(
        "plugin_consent_event",
        "plugin_consent_event",
        "refmd.plugin.consent_event",
        "none",
        @owner_device
      ),
      surface(
        "plugin_network_proxy_request",
        "plugin_network_proxy_request",
        "refmd.plugin.network_proxy_request",
        "none",
        @owner_device
      ),
      surface(
        "responder_prekey",
        "responder_prekey",
        "refmd.ake.responder_prekey",
        "none",
        @owner_device
      ),
      surface(
        "initiator_ake_commitment",
        "initiator_ake_commitment",
        "refmd.ake.initiator_commitment",
        "none",
        @owner_device
      ),
      initial_key_delivery_surface("umk_distribution"),
      initial_key_delivery_surface("device_approval_kek_initial"),
      initial_key_delivery_surface("trust_transfer"),
      surface(
        "pin_gossip_statement",
        "pin_gossip_statement",
        "refmd.pin.gossip_statement",
        "none",
        @owner_device
      ),
      surface(
        "device_key_deletion_proof",
        "device_key_deletion_proof",
        "refmd.device.key_deletion.device_key",
        "device_key_deletion_proof",
        @owner_device
      ),
      surface(
        "device_key_deletion_proof",
        "device_key_deletion_proof",
        "refmd.device.key_deletion.identity_key",
        "identity_key_deletion_proof",
        @owner_device
      ),
      surface(
        "recovery_device_approval",
        "recovery_device_approval",
        "refmd.device.recovery_approval",
        "none",
        @owner_identity
      ),
      surface(
        "device_revocation",
        "device_revocation",
        "refmd.device.revocation",
        "none",
        @owner_device
      ),
      surface(
        "recovery_session",
        "recovery_session",
        "refmd.recovery.session",
        "none",
        @owner_identity
      ),
      surface(
        "recovery_authorization_proof",
        "recovery_authorization_proof",
        "refmd.recovery.authorization_proof",
        "none",
        @owner_identity
      ),
      surface(
        "document_update",
        "document_update",
        "refmd.document.update.workspace_device",
        "workspace_device",
        @owner_device
      ),
      surface(
        "document_update",
        "document_update",
        "refmd.document.update.share_participant_device",
        "share_participant_device",
        @owner_share_participant_device
      ),
      surface(
        "document_snapshot",
        "document_snapshot",
        "refmd.document.snapshot.workspace_device",
        "workspace_device",
        @owner_device
      ),
      surface(
        "document_snapshot",
        "document_snapshot",
        "refmd.document.snapshot.share_participant_device",
        "share_participant_device",
        @owner_share_participant_device
      ),
      surface(
        "editor_ephemeral",
        "editor_ephemeral",
        "refmd.editor.ephemeral.workspace_device",
        "workspace_device",
        @owner_device
      ),
      surface(
        "editor_ephemeral",
        "editor_ephemeral",
        "refmd.editor.ephemeral.share_participant_device",
        "share_participant_device",
        @owner_share_participant_device
      ),
      surface(
        "editor_ephemeral_session",
        "editor_ephemeral_session",
        "refmd.editor.ephemeral_session.workspace_device",
        "workspace_device",
        @owner_device
      ),
      surface(
        "editor_ephemeral_session",
        "editor_ephemeral_session",
        "refmd.editor.ephemeral_session.share_participant_device",
        "share_participant_device",
        @owner_share_participant_device
      )
    ]
  end

  defp active_surfaces do
    Enum.map(static_surfaces(), fn %{surface: surface} -> surface end)
  end

  def get_active!(signing_purpose, variant)
      when is_binary(signing_purpose) and is_binary(variant) do
    active_by_purpose_variant =
      Map.new(active_surfaces(), fn surface ->
        {{surface.signing_purpose, surface.variant}, surface}
      end)

    case active_by_purpose_variant[{signing_purpose, variant}] do
      nil -> raise(ArgumentError, "signing_surface_not_active")
      surface -> surface
    end
  end

  def get_active!(_, _), do: raise(ArgumentError, "signing_surface_not_active")

  def semantic_validator!(%{signing_purpose: signing_purpose, variant: variant}) do
    {function, arity} =
      signing_purpose
      |> semantic_validator_id(variant)
      |> semantic_validator_for!()

    %{
      module: RefMD.Crypto.Signature.SemanticValidator,
      function: function,
      arity: arity
    }
  end

  def semantic_validator!(_), do: raise(ArgumentError, "signing_surface_validator_not_registered")

  def transcript_builder!(%{signing_purpose: signing_purpose, variant: variant}) do
    {module, function, arity} = transcript_builder_for!(signing_purpose, variant)

    %{
      module: module,
      function: function,
      arity: arity
    }
  end

  def transcript_builder!(_), do: raise(ArgumentError, "signing_surface_builder_not_registered")

  if Mix.env() == :test do
    @doc false
    def __test_active_surfaces__, do: active_surfaces()

    @doc false
    def __test_owner_kinds__(signing_purpose, variant),
      do: owner_kinds!(signing_purpose, variant)
  end

  defp semantic_validator_for!(id)
       when id in [
              "pq_wrap:none:semantic"
            ],
       do: {:validate_pq_wrap!, 4}

  defp semantic_validator_for!(id)
       when id in [
              "workspace_pin_bootstrap:none:semantic"
            ],
       do: {:validate_workspace_pin_bootstrap!, 5}

  defp semantic_validator_for!(id)
       when id in [
              "key_directory_checkpoint:device_authorized:semantic",
              "key_directory_checkpoint:identity_initial:semantic",
              "key_directory_checkpoint:identity_active:semantic",
              "key_directory_checkpoint:identity_rotation:semantic",
              "key_directory_checkpoint:workspace_initial:semantic",
              "key_directory_checkpoint:workspace_authorized:semantic",
              "key_directory_checkpoint:invitation_redeem_authority:semantic",
              "key_directory_checkpoint:share_participant_document_operation:semantic"
            ],
       do: {:validate_key_directory_checkpoint!, 5}

  defp semantic_validator_for!("key_directory_event:" <> rest) do
    if exact_variant_semantic?(rest, @key_directory_event_variants),
      do: {:validate_key_directory_event!, 5},
      else: raise(ArgumentError, "semantic_validator_missing")
  end

  defp semantic_validator_for!("recipient_bound_authorization:none:semantic"),
    do: {:validate_recipient_bound_authorization!, 4}

  defp semantic_validator_for!("share_capability_authorization:none:semantic"),
    do: {:validate_share_capability_authorization!, 5}

  defp semantic_validator_for!("share_participant_device_authorization:none:semantic"),
    do: {:validate_share_participant_device_authorization!, 5}

  defp semantic_validator_for!("rrp_request:" <> rest) do
    if exact_variant_semantic?(rest, @rrp_request_variants),
      do: {:validate_rrp!, 5},
      else: raise(ArgumentError, "semantic_validator_missing")
  end

  defp semantic_validator_for!("genesis_device_bootstrap:none:semantic"),
    do: {:validate_genesis_device_bootstrap!, 5}

  defp semantic_validator_for!("recovery_session:none:semantic"),
    do: {:validate_recovery_session!, 5}

  defp semantic_validator_for!("recovery_authorization_proof:none:semantic"),
    do: {:validate_recovery_authorization_proof!, 4}

  defp semantic_validator_for!("responder_prekey:none:semantic"),
    do: {:validate_ake_prekey!, 4}

  defp semantic_validator_for!("initiator_ake_commitment:none:semantic"),
    do: {:validate_ake_commitment!, 4}

  defp semantic_validator_for!("pin_gossip_statement:none:semantic"),
    do: {:validate_pin_gossip!, 4}

  defp semantic_validator_for!(id)
       when id in [
              "device_key_deletion_proof:device_key_deletion_proof:semantic",
              "device_key_deletion_proof:identity_key_deletion_proof:semantic"
            ],
       do: {:validate_key_deletion!, 5}

  defp semantic_validator_for!("device_revocation:none:semantic"),
    do: {:validate_device_revocation!, 5}

  defp semantic_validator_for!(id)
       when id in [
              "editor_ephemeral:workspace_device:semantic",
              "editor_ephemeral:share_participant_device:semantic",
              "editor_ephemeral_session:workspace_device:semantic",
              "editor_ephemeral_session:share_participant_device:semantic"
            ],
       do: {:validate_ephemeral!, 5}

  defp semantic_validator_for!(id), do: semantic_validator_for_explicit!(id)

  defp semantic_validator_for_explicit!(id)
       when id in [
              "device_approval:none:semantic"
            ],
       do: {:validate_device_approval!, 5}

  defp semantic_validator_for_explicit!("recovery_device_approval:none:semantic"),
    do: {:validate_recovery_approval!, 5}

  defp semantic_validator_for_explicit!("plugin_bundle_approval:none:semantic"),
    do: {:validate_plugin_bundle_approval!, 5}

  defp semantic_validator_for_explicit!("plugin_consent_event:none:semantic"),
    do: {:validate_plugin_consent_event!, 5}

  defp semantic_validator_for_explicit!("plugin_network_proxy_request:none:semantic"),
    do: {:validate_plugin_network_proxy_request!, 5}

  defp semantic_validator_for_explicit!(id)
       when id in [
              "document_update:workspace_device:semantic",
              "document_update:share_participant_device:semantic",
              "document_snapshot:workspace_device:semantic",
              "document_snapshot:share_participant_device:semantic"
            ],
       do: {:validate_document_admission!, 5}

  defp semantic_validator_for_explicit!(id)
       when id in [
              "initial_key_delivery:umk_distribution:semantic",
              "initial_key_delivery:device_approval_kek_initial:semantic",
              "initial_key_delivery:trust_transfer:semantic"
            ],
       do: {:validate_initial_key_delivery!, 5}

  defp semantic_validator_for_explicit!(_), do: raise(ArgumentError, "semantic_validator_missing")

  defp exact_variant_semantic?(id_suffix, variants) do
    String.ends_with?(id_suffix, ":semantic") and
      String.replace_suffix(id_suffix, ":semantic", "") in variants
  end

  defp semantic_validator_id(signing_purpose, variant),
    do: signing_purpose <> ":" <> variant <> ":semantic"

  def assert_owner_kind!(%{signing_purpose: signing_purpose, variant: variant}, owner_kind)
      when is_binary(owner_kind) do
    accepted = owner_kinds!(signing_purpose, variant)

    if owner_kind in accepted,
      do: :ok,
      else: raise(ArgumentError, "signing_surface_owner_kind_mismatch")
  end

  def assert_owner_kind!(_, _), do: raise(ArgumentError, "signing_surface_owner_kind_mismatch")

  defp surface(surface_id, signing_purpose, transcript_owner, variant, accepted_owner_kinds) do
    %{
      surface: %{
        surface_id: surface_id,
        signing_purpose: signing_purpose,
        transcript_owner: transcript_owner,
        owner_kind: hd(accepted_owner_kinds),
        variant: variant,
        suite_id: @suite_id,
        protocol_version: @protocol_version
      },
      owner_kinds: accepted_owner_kinds
    }
  end

  defp owner_kinds!(signing_purpose, variant) do
    owner_kind_by_surface =
      Map.new(static_surfaces(), fn %{surface: surface, owner_kinds: owner_kinds} ->
        {{surface.signing_purpose, surface.variant}, owner_kinds}
      end)

    case owner_kind_by_surface[{signing_purpose, variant}] do
      nil -> raise(ArgumentError, "signing_surface_owner_kind_mismatch")
      owner_kinds -> owner_kinds
    end
  end

  defp key_directory_event_surface(event_type)
       when event_type in [
              "document_write_session_admitted",
              "document_snapshot_accepted"
            ] do
    surface(
      "key_directory_event",
      "key_directory_event",
      "refmd.key_directory.event.#{event_type}",
      event_type,
      @owner_key_directory_document_event
    )
  end

  defp key_directory_event_surface(event_type)
       when event_type in ["workspace_invitation_redeemed", "guest_invitation_redeemed"] do
    surface(
      "key_directory_event",
      "key_directory_event",
      "refmd.key_directory.event." <> event_type,
      event_type,
      @owner_key_directory_invitation_redeem_event
    )
  end

  defp key_directory_event_surface(event_type) do
    surface(
      "key_directory_event",
      "key_directory_event",
      "refmd.key_directory.event." <> event_type,
      event_type,
      @owner_key_directory_event
    )
  end

  defp initial_key_delivery_surface(variant) do
    surface(
      "initial_key_delivery",
      "initial_key_delivery",
      "refmd.initial_key_delivery." <> variant,
      variant,
      @owner_device
    )
  end

  defp transcript_builder_for!("pq_wrap", "none"),
    do: {RefMD.Crypto.Signature.KeyDirectory, :build_pq_wrap_transcript!, 4}

  defp transcript_builder_for!("key_directory_checkpoint", variant)
       when variant in [
              "identity_initial",
              "workspace_initial",
              "identity_active",
              "identity_rotation",
              "workspace_authorized",
              "invitation_redeem_authority",
              "share_participant_document_operation",
              "device_authorized"
            ],
       do: {RefMD.Crypto.Signature.KeyDirectory, :build_key_directory_checkpoint_transcript!, 4}

  defp transcript_builder_for!("workspace_pin_bootstrap", "none"),
    do: {RefMD.Crypto.Signature.KeyDirectory, :build_workspace_pin_bootstrap_transcript!, 3}

  defp transcript_builder_for!("key_directory_event", variant)
       when variant in [
              "wrap_issued",
              "identity_key_added",
              "device_key_added",
              "member_added",
              "member_role_changed",
              "member_removed",
              "signing_key_revoked",
              "encryption_key_revoked",
              "suite_policy_changed",
              "share_created",
              "share_metadata_updated",
              "share_key_scope_added",
              "share_key_scope_replaced",
              "share_key_scope_removed",
              "share_exclusion_changed",
              "share_revoked",
              "recipient_bound_delivery_admitted",
              "workspace_invitation_created",
              "workspace_invitation_bootstrap_updated",
              "workspace_invitation_revoked",
              "workspace_invitation_redeemed",
              "guest_invitation_created",
              "guest_invitation_bootstrap_updated",
              "guest_invitation_revoked",
              "guest_invitation_redeemed",
              "guest_grant_revoked",
              "guest_device_revoked",
              "rotation_started",
              "rotation_completed",
              "old_key_deleted",
              "document_write_session_admitted",
              "document_write_state_changed",
              "document_snapshot_accepted"
            ],
       do: {RefMD.Crypto.Signature.KeyDirectory, :build_key_directory_event_transcript!, 4}

  defp transcript_builder_for!("recipient_bound_authorization", "none"),
    do: {RefMD.Crypto.Signature.Share, :build_recipient_bound_authorization_transcript!, 5}

  defp transcript_builder_for!("share_capability_authorization", "none"),
    do: {RefMD.Crypto.Signature.Share, :build_share_capability_authorization_transcript!, 1}

  defp transcript_builder_for!("share_participant_device_authorization", "none"),
    do:
      {RefMD.Crypto.Signature.Share, :build_share_participant_device_authorization_transcript!, 1}

  defp transcript_builder_for!("rrp_request", variant)
       when variant in [
              "http_user_device",
              "http_share_participant_device",
              "channel_user_device",
              "channel_share_participant_device"
            ],
       do: {RefMD.Crypto.Signature.Device, :build_rrp_transcript!, 7}

  defp transcript_builder_for!("genesis_device_bootstrap", "none"),
    do: {RefMD.Crypto.Signature.Device, :build_genesis_device_bootstrap_transcript!, 1}

  defp transcript_builder_for!("device_approval", "none"),
    do: {RefMD.Crypto.Signature.Device, :build_device_approval_transcript!, 7}

  defp transcript_builder_for!("plugin_bundle_approval", "none"),
    do: {RefMD.Crypto.Signature.Plugin, :build_plugin_bundle_approval_transcript!, 1}

  defp transcript_builder_for!("plugin_consent_event", "none"),
    do: {RefMD.Crypto.Signature.Plugin, :build_plugin_consent_event_transcript!, 1}

  defp transcript_builder_for!("plugin_network_proxy_request", "none"),
    do: {RefMD.Crypto.Signature.Plugin, :build_plugin_network_proxy_request_transcript!, 1}

  defp transcript_builder_for!("responder_prekey", "none"),
    do: {RefMD.Crypto.Signature.KeyDirectory, :build_responder_prekey_transcript!, 4}

  defp transcript_builder_for!("initiator_ake_commitment", "none"),
    do: {RefMD.Crypto.Signature.KeyDirectory, :build_initiator_ake_commitment_transcript!, 5}

  defp transcript_builder_for!("initial_key_delivery", variant)
       when variant in ["umk_distribution", "device_approval_kek_initial", "trust_transfer"],
       do: {RefMD.Crypto.Signature.KeyDirectory, :build_initial_key_delivery_transcript!, 8}

  defp transcript_builder_for!("pin_gossip_statement", "none"),
    do: {RefMD.Crypto.Signature.KeyDirectory, :build_pin_gossip_statement_transcript!, 2}

  defp transcript_builder_for!("device_key_deletion_proof", variant)
       when variant in ["device_key_deletion_proof", "identity_key_deletion_proof"],
       do: {RefMD.Crypto.Signature.Recovery, :build_device_key_deletion_proof_transcript!, 2}

  defp transcript_builder_for!("recovery_device_approval", "none"),
    do: {RefMD.Crypto.Signature.Recovery, :build_recovery_device_approval_transcript!, 1}

  defp transcript_builder_for!("device_revocation", "none"),
    do: {RefMD.Crypto.Signature.Device, :build_device_revocation_transcript!, 6}

  defp transcript_builder_for!("recovery_session", "none"),
    do: {RefMD.Crypto.Signature.Recovery, :build_recovery_session_transcript!, 1}

  defp transcript_builder_for!("recovery_authorization_proof", "none"),
    do: {RefMD.Crypto.Signature.Recovery, :build_recovery_authorization_proof_transcript!, 1}

  defp transcript_builder_for!("document_update", variant)
       when variant in ["workspace_device", "share_participant_device"],
       do: {RefMD.Crypto.Signature.Collaboration, :build_document_update_transcript!, 1}

  defp transcript_builder_for!("document_snapshot", variant)
       when variant in ["workspace_device", "share_participant_device"],
       do: {RefMD.Crypto.Signature.Collaboration, :build_document_snapshot_transcript!, 1}

  defp transcript_builder_for!("editor_ephemeral", variant)
       when variant in ["workspace_device", "share_participant_device"],
       do: {RefMD.Crypto.Signature.Collaboration, :build_editor_ephemeral_transcript!, 1}

  defp transcript_builder_for!("editor_ephemeral_session", variant)
       when variant in ["workspace_device", "share_participant_device"],
       do: {RefMD.Crypto.Signature.Collaboration, :build_editor_ephemeral_session_transcript!, 1}

  defp transcript_builder_for!(_, _),
    do: raise(ArgumentError, "signing_surface_builder_not_registered")
end
