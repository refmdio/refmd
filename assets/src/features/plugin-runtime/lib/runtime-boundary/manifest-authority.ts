import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictValueBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type {
  PluginDocumentScope,
  PluginHighRiskConsent,
  PluginPermission,
} from "../capability/capability-enforcement";
import { isKnownPluginPermission } from "../capability/capability-enforcement";
import type { PluginNetworkEndpointPolicy } from "../network/host-network";
import type { PluginRendererSlot } from "../renderer/host-renderer";

export interface PluginManifestAuthorityHashes {
  permissionsHash: string;
  endpointHash: string;
  rendererSlotsHash: string;
  documentScopeHash: string;
}

export interface PluginManifestAuthority {
  hashes: PluginManifestAuthorityHashes;
  permissions: readonly PluginPermission[];
  documentScope?: PluginDocumentScope;
  networkEndpoints: readonly PluginNetworkEndpointPolicy[];
  rendererSlots: readonly PluginRendererSlot[];
  highRiskConsents: readonly PluginHighRiskConsent[];
}

export function derivePluginManifestAuthority(manifest: StrictJsonValue): PluginManifestAuthority {
  const manifestRecord = requireRecord(manifest, "plugin_manifest_invalid");
  const permissionsValue = arrayValue(manifestRecord.permissions);
  const networkValue = isRecord(manifestRecord.network) ? manifestRecord.network : {};
  const endpointValue = arrayValue(networkValue.endpoints);
  const rendererSlotValue = arrayValue(manifestRecord.rendererSlots);
  const documentScopeValue = arrayValue(manifestRecord.documentScopes);
  const permissions = manifestPermissions(permissionsValue);

  return {
    hashes: {
      permissionsHash: semanticHash(permissionsValue),
      endpointHash: semanticHash(endpointValue),
      rendererSlotsHash: semanticHash(rendererSlotValue),
      documentScopeHash: semanticHash(documentScopeValue),
    },
    permissions,
    documentScope: manifestDocumentScope(documentScopeValue),
    networkEndpoints: endpointValue.flatMap(manifestNetworkEndpoint),
    rendererSlots: rendererSlotValue.flatMap(manifestRendererSlot),
    highRiskConsents: inferredHighRiskConsents(permissions),
  };
}

function manifestPermissions(value: readonly StrictJsonValue[]): readonly PluginPermission[] {
  const permissions = stringList(value);
  if (!permissions.every(isKnownPluginPermission)) {
    throw new Error("plugin_manifest_permission_invalid");
  }
  return permissions;
}

export function assertPluginManifestAuthorityHashes(
  authority: PluginManifestAuthority,
  expected: PluginManifestAuthorityHashes,
): void {
  assertEqual(
    authority.hashes.permissionsHash,
    expected.permissionsHash,
    "permissions_hash_mismatch",
  );
  assertEqual(authority.hashes.endpointHash, expected.endpointHash, "endpoint_hash_mismatch");
  assertEqual(
    authority.hashes.rendererSlotsHash,
    expected.rendererSlotsHash,
    "renderer_slots_hash_mismatch",
  );
  assertEqual(
    authority.hashes.documentScopeHash,
    expected.documentScopeHash,
    "document_scope_hash_mismatch",
  );
}

export function semanticHash(value: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictValueBytes(value));
}

function manifestDocumentScope(
  scopes: readonly StrictJsonValue[],
): PluginDocumentScope | undefined {
  const scope: PluginDocumentScope = {};
  for (const entry of scopes) {
    if (!isRecord(entry)) continue;
    mergeDocumentScope(scope, entry);
  }
  return Object.keys(scope).length > 0 ? scope : undefined;
}

function mergeDocumentScope(
  scope: PluginDocumentScope,
  entry: Record<string, StrictJsonValue>,
): void {
  const kind = typeof entry.kind === "string" ? entry.kind : "";
  if (kind === "workspace") {
    scope.workspaceReadAllowed = true;
    return;
  }
  if (kind === "active_document" || kind === "activeDocument" || kind === "active") {
    const documentId = documentScopeId(entry);
    scope.activeDocumentReadAllowed = true;
    if (documentId && !["active", "active_document", "activeDocument"].includes(documentId)) {
      scope.activeDocumentId = documentId;
    }
    return;
  }
  if (kind === "selected_documents" || kind === "selectedDocuments" || kind === "selected") {
    const documentIds = documentScopeIds(entry);
    scope.selectedDocumentsReadAllowed = true;
    const semanticIds = new Set(["selected", "selected_documents", "selectedDocuments"]);
    const selectedDocumentIds = documentIds.filter((id) => !semanticIds.has(id));
    if (selectedDocumentIds.length > 0) scope.selectedDocumentIds = selectedDocumentIds;
    return;
  }
  if (
    kind === "allowed_documents" ||
    kind === "allowedDocuments" ||
    kind === "allowed_document" ||
    kind === "document"
  ) {
    const allowedDocumentIds = documentScopeIds(entry);
    if (allowedDocumentIds.length > 0) scope.allowedDocumentIds = allowedDocumentIds;
  }
}

function documentScopeId(scope: Record<string, StrictJsonValue>): string | null {
  for (const key of ["documentId", "document_id", "id"]) {
    const value = scope[key];
    if (typeof value === "string" && value !== "") return value;
  }
  return null;
}

function documentScopeIds(scope: Record<string, StrictJsonValue>): readonly string[] {
  for (const key of ["documentIds", "document_ids", "ids", "documentId", "document_id", "id"]) {
    const value = scope[key];
    const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
    const ids = uniqueStrings(values);
    if (ids.length > 0) return ids;
  }
  return [];
}

function manifestNetworkEndpoint(value: StrictJsonValue): readonly PluginNetworkEndpointPolicy[] {
  if (!isRecord(value)) return [];
  const id = stringValue(value.id);
  const url = stringValue(value.url);
  if (!id || !url) return [];
  const credentialAudience = stringValue(value.credentialAudience);
  return [
    {
      id,
      url,
      methods: stringList(arrayOrScalarValue(value.methods)),
      routes: manifestNetworkRoutes(value.routes),
      headers: endpointStringList(value, "headers", "allowedHeaders"),
      bodySchema:
        value.bodySchema === "json" || value.bodySchema === "text" ? value.bodySchema : "none",
      maxRequestBytes: positiveInteger(value.maxRequestBytes, 64 * 1024),
      maxResponseBytes: positiveInteger(value.maxResponseBytes, 512 * 1024),
      ...(credentialAudience ? { credentialAudience } : {}),
    },
  ];
}

function manifestRendererSlot(value: StrictJsonValue): readonly PluginRendererSlot[] {
  if (
    !isRecord(value) ||
    (value.kind !== "block" && value.kind !== "inline") ||
    typeof value.type !== "string" ||
    value.type === "" ||
    (value.kind === "inline" && value.type !== "code")
  ) {
    return [];
  }
  return [{ kind: value.kind, type: value.type }];
}

function inferredHighRiskConsents(
  permissions: readonly PluginPermission[],
): readonly PluginHighRiskConsent[] {
  const plaintextRead = permissions.some(plaintextReadPermission);
  const networkFetch = permissions.includes("network:fetch");
  const cacheStorageWrite = permissions.includes("storage:write:cache");
  const workspaceRead = permissions.includes("document:read:workspace");
  const documentWrite = permissions.includes("document:write");
  return [
    plaintextRead && documentWrite ? "plaintext_document_write" : null,
    plaintextRead && networkFetch ? "plaintext_network_egress" : null,
    plaintextRead && cacheStorageWrite ? "plaintext_cache_storage" : null,
    workspaceRead && networkFetch ? "workspace_network_egress" : null,
  ].filter((value): value is PluginHighRiskConsent => value !== null);
}

function plaintextReadPermission(permission: string): boolean {
  return (
    permission === "document:read:active" ||
    permission === "document:read:selected" ||
    permission === "document:read:workspace" ||
    permission.startsWith("plaintext:render:") ||
    permission === "editor:selection:read" ||
    permission === "editor:context:read"
  );
}

function endpointStringList(
  value: Record<string, StrictJsonValue>,
  primaryKey: string,
  secondaryKey: string,
): readonly string[] {
  const primary = value[primaryKey];
  if (Array.isArray(primary)) return stringList(primary);
  const secondary = value[secondaryKey];
  return Array.isArray(secondary) ? stringList(secondary) : [];
}

function manifestNetworkRoutes(value: StrictJsonValue | undefined): readonly ["proxy"] {
  if (!Array.isArray(value) || value.length !== 1 || value[0] !== "proxy") {
    throw new Error("plugin_manifest_network_route_invalid");
  }
  return ["proxy"];
}

function positiveInteger(value: StrictJsonValue | undefined, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

function arrayValue(value: StrictJsonValue | undefined): StrictJsonValue[] {
  return Array.isArray(value) ? value : [];
}

function arrayOrScalarValue(value: StrictJsonValue | undefined): StrictJsonValue[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function stringList(value: readonly StrictJsonValue[]): readonly string[] {
  return uniqueStrings(value);
}

function uniqueStrings(value: readonly StrictJsonValue[]): readonly string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry === "string" && entry !== "" && !seen.has(entry)) {
      seen.add(entry);
      result.push(entry);
    }
  }
  return result;
}

function stringValue(value: StrictJsonValue | undefined): string {
  return typeof value === "string" && value !== "" ? value : "";
}

function isRecord(value: StrictJsonValue | undefined): value is Record<string, StrictJsonValue> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireRecord(value: StrictJsonValue, code: string): Record<string, StrictJsonValue> {
  if (!isRecord(value)) throw new Error(code);
  return value;
}

function assertEqual(actual: string, expected: string, code: string): void {
  if (actual !== expected) throw new Error(code);
}
