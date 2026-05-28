import { E2E_TIMEOUTS } from "../timeouts";

export const EMPTY_SEMANTIC_HASH = "1T0YwjIS6ntjAFlLuJvOYCGPbv8rnWKLjMQtPnm71as";

export const PLUGIN_COMMAND_STATUS_TIMEOUT_MS = E2E_TIMEOUTS.extendedScenario;

export const PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS = E2E_TIMEOUTS.accountSetup;

export const PLUGIN_LOCAL_STATE_CLEANUP_TIMEOUT_MS = E2E_TIMEOUTS.accountSetup;

export interface ConsentDescriptor {
  plugin_id: string;
  package_id: string;
  application_id: string;
  activation_id: string;
  capability_grant_id: string;
  owner_scope_kind: string;
  application_scope_kind: string;
  workspace_id: string;
  state_head_hash: string;
  approval_event_hash: string;
  consent_head_hash: string | null;
  consent_epoch: number | null;
  version: string;
  bundle_hash: string;
  manifest_hash: string;
  resource_manifest_hash: string;
  permissions_hash: string;
  endpoint_hash: string;
  renderer_slots_hash: string;
  document_scope_hash: string;
  signer_user_id: string;
  signer_device_id: string;
  title: string;
  author: string;
  permissions: string[];
  network_endpoints: Record<string, unknown>[];
  renderer_slots: Record<string, unknown>[];
  document_scopes: Record<string, unknown>[];
  high_risk_consents: string[];
}
