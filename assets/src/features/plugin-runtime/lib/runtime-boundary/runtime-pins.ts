import { authState } from "@/entities/session";
import {
  getPluginConsentPin,
  getPluginStatePin,
  savePluginConsentPin,
  savePluginStatePin,
} from "@/shared/lib/crypto/trust-store";
import type {
  PluginRuntimeBundleEnvelope,
  PluginRuntimeApplicationDescriptor,
  PluginRuntimeLocalPins,
  PluginRuntimePinWriter,
} from "./runtime-types";

export function assertRuntimeLocalPins(
  descriptor: PluginRuntimeApplicationDescriptor,
  envelope: PluginRuntimeBundleEnvelope | null,
  localPins: PluginRuntimeLocalPins | null,
): asserts localPins is PluginRuntimeLocalPins {
  if (!localPins?.state) throw new Error("plugin_state_pin_required");
  if (!localPins?.consent) throw new Error("plugin_consent_pin_required");
  assertEqual(localPins.state.workspaceId, descriptor.workspaceId, "state_pin_workspace_mismatch");
  assertEqual(localPins.state.packageId, descriptor.packageId, "state_pin_package_mismatch");
  assertEqual(
    localPins.state.applicationId,
    descriptor.applicationId,
    "state_pin_application_mismatch",
  );
  assertEqual(
    localPins.state.activationId,
    descriptor.activationId,
    "state_pin_activation_mismatch",
  );
  assertEqual(
    localPins.consent.workspaceId,
    descriptor.workspaceId,
    "consent_pin_workspace_mismatch",
  );
  assertEqual(localPins.consent.packageId, descriptor.packageId, "consent_pin_package_mismatch");
  assertEqual(
    localPins.consent.applicationId,
    descriptor.applicationId,
    "consent_pin_application_mismatch",
  );
  assertEqual(
    localPins.consent.activationId,
    descriptor.activationId,
    "consent_pin_activation_mismatch",
  );
  assertEqual(descriptor.stateHeadHash, localPins.state.latestEventHash, "state_pin_mismatch");
  assertEqual(
    descriptor.consentHeadHash,
    localPins.consent.latestEventHash,
    "consent_pin_mismatch",
  );
  if (envelope) {
    assertEqual(envelope.state_head_hash, localPins.state.latestEventHash, "state_head_mismatch");
    assertEqual(
      envelope.consent_event_hash,
      localPins.consent.latestEventHash,
      "consent_head_mismatch",
    );
    assertEqual(envelope.bundle_hash, localPins.state.bundleHash, "bundle_pin_mismatch");
    assertEqual(
      envelope.approval_event_hash,
      localPins.state.approvalEventHash,
      "approval_pin_mismatch",
    );
    assertEqual(envelope.consent_epoch, localPins.consent.consentEpoch, "consent_epoch_mismatch");
  }
}

export async function loadPluginRuntimeLocalPins(
  descriptor: PluginRuntimeApplicationDescriptor,
): Promise<PluginRuntimeLocalPins> {
  const auth = authState();
  if (!auth?.user.id) throw new Error("plugin_consent_pin_required");

  const [state, consent] = await Promise.all([
    getPluginStatePin(
      descriptor.workspaceId,
      descriptor.packageId,
      descriptor.applicationId,
      descriptor.activationId,
    ),
    getPluginConsentPin(
      descriptor.workspaceId,
      descriptor.packageId,
      descriptor.applicationId,
      descriptor.activationId,
      auth.user.id,
    ),
  ]);
  const pins = state && consent ? { state, consent } : null;
  assertRuntimeLocalPins(descriptor, null, pins);
  return pins;
}

export async function saveVerifiedPluginRuntimePins(
  descriptor: PluginRuntimeApplicationDescriptor,
  envelope: PluginRuntimeBundleEnvelope,
  userId: string | null = authState()?.user.id ?? null,
  nowMs: number = Date.now(),
  writer: PluginRuntimePinWriter = {
    saveState: savePluginStatePin,
    saveConsent: savePluginConsentPin,
  },
): Promise<void> {
  if (!userId) throw new Error("plugin_consent_pin_user_required");

  assertEqual(envelope.plugin_id, descriptor.pluginId, "plugin_id_mismatch");
  assertEqual(envelope.application_id, descriptor.applicationId, "application_id_mismatch");
  assertEqual(envelope.workspace_id, descriptor.workspaceId, "workspace_id_mismatch");
  assertEqual(envelope.state_head_hash, descriptor.stateHeadHash, "state_head_mismatch");
  assertEqual(envelope.consent_event_hash, descriptor.consentHeadHash, "consent_head_mismatch");
  assertEqual(
    envelope.approval_proof.event_hash,
    envelope.approval_event_hash,
    "approval_hash_mismatch",
  );
  assertEqual(
    envelope.consent_proof.event_hash,
    envelope.consent_event_hash,
    "consent_hash_mismatch",
  );

  await writer.saveState({
    workspaceId: envelope.workspace_id,
    packageId: envelope.package_id,
    applicationId: envelope.application_id,
    activationId: envelope.activation_id,
    latestEventHash: envelope.state_head_hash,
    bundleHash: envelope.bundle_hash,
    approvalEventHash: envelope.approval_event_hash,
    updatedAtMs: nowMs,
  });
  await writer.saveConsent({
    workspaceId: envelope.workspace_id,
    packageId: envelope.package_id,
    applicationId: envelope.application_id,
    activationId: envelope.activation_id,
    userId,
    consentEpoch: envelope.consent_epoch,
    latestEventHash: envelope.consent_event_hash,
    updatedAtMs: nowMs,
  });
}

function assertEqual(actual: unknown, expected: unknown, error: string): void {
  if (actual !== expected) throw new Error(error);
}
