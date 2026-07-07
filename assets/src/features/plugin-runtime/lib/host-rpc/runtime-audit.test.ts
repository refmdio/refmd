import { describe, expect, it, vi } from "vite-plus/test";
import type { PluginAuditEvent } from "../capability/capability-enforcement";
import {
  beginPluginRuntimeApplicationRevocation,
  releasePluginRuntimeApplicationRevocation,
} from "../runtime-boundary/runtime-workspace-revocation";
import { createDurablePluginRuntimeAuditSink } from "./runtime-audit";

describe("createDurablePluginRuntimeAuditSink", () => {
  it("fails closed without posting audit while the application is being revoked", async () => {
    const postAudit = vi.fn(async () => ({
      response: new Response(null, { status: 200 }),
    }));
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);

    beginPluginRuntimeApplicationRevocation("application-one");
    try {
      await expect(
        sink({
          applicationId: "application-one",
          workspaceId: "workspace-one",
          type: "plugin.bundle.imported",
        } as PluginAuditEvent),
      ).resolves.toBe(false);
      await sink.flushPendingAudit();
    } finally {
      releasePluginRuntimeApplicationRevocation("application-one");
      releasePluginRuntimeApplicationRevocation("application-one");
    }

    expect(postAudit).not.toHaveBeenCalled();
  });

  it("fails closed without posting late audit immediately after application revocation release", async () => {
    vi.useFakeTimers();
    const postAudit = vi.fn(async () => ({
      response: new Response(null, { status: 200 }),
    }));
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);

    beginPluginRuntimeApplicationRevocation("application-one");
    releasePluginRuntimeApplicationRevocation("application-one");
    try {
      await expect(
        sink({
          applicationId: "application-one",
          workspaceId: "workspace-one",
          type: "plugin.bundle.imported",
        } as PluginAuditEvent),
      ).resolves.toBe(false);
      await sink.flushPendingAudit();
    } finally {
      releasePluginRuntimeApplicationRevocation("application-one");
      vi.runOnlyPendingTimers();
      vi.useRealTimers();
    }

    expect(postAudit).not.toHaveBeenCalled();
  });

  it("keeps pending audit flushable but fails closed for new audit after close", async () => {
    let resolvePost!: () => void;
    const postAudit = vi.fn(
      () =>
        new Promise<{ response: Response }>((resolve) => {
          resolvePost = () => resolve({ response: new Response(null, { status: 200 }) });
        }),
    );
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);

    const pending = sink(runtimeAuditEvent());
    sink.close("plugin_application_deleted");
    await expect(sink(runtimeAuditEvent({ event_id: "event-late" }))).resolves.toBe(false);
    expect(postAudit).toHaveBeenCalledTimes(1);

    resolvePost();
    await expect(pending).resolves.toBe(true);
    await sink.flushPendingAudit();
    expect(postAudit).toHaveBeenCalledTimes(1);
  });

  it("waits for an idle window after pending audit settles", async () => {
    vi.useFakeTimers();
    try {
      let resolvePost!: () => void;
      const postAudit = vi.fn(
        () =>
          new Promise<{ response: Response }>((resolve) => {
            resolvePost = () => resolve({ response: new Response(null, { status: 200 }) });
          }),
      );
      const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);

      const pending = sink(runtimeAuditEvent());
      let idleResolved = false;
      const idle = sink.waitForIdleAudit(25).then(() => {
        idleResolved = true;
      });

      await Promise.resolve();
      expect(idleResolved).toBe(false);

      resolvePost();
      await expect(pending).resolves.toBe(true);
      await Promise.resolve();
      expect(idleResolved).toBe(false);

      await vi.advanceTimersByTimeAsync(24);
      expect(idleResolved).toBe(false);

      await vi.advanceTimersByTimeAsync(1);
      await idle;
      expect(idleResolved).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

function runtimeAuditEvent(overrides: Partial<PluginAuditEvent> = {}): PluginAuditEvent {
  return {
    protocol: "refmd.plugin.audit",
    version: 1,
    event_id: "event-one",
    class: "security",
    type: "plugin.bundle.imported",
    actor: {
      user_id: "user-one",
      device_id: "device-one",
      session_id: "session-one",
      principal_kind: "user",
      principal_id: "user-one",
    },
    pluginId: "plugin-one",
    packageId: "package-one",
    applicationId: "application-one",
    activationId: "activation-one",
    ownerScopeKind: "workspace",
    stateHeadHash: "state-one",
    consentHeadHash: "consent-one",
    capabilityGrantId: "grant-one",
    consentEpoch: 1,
    frameGeneration: 1,
    frameScope: "primary",
    workspaceId: "workspace-one",
    bundleHash: "bundle-one",
    manifestHash: "manifest-one",
    capabilityId: "capability-one",
    requestId: "request-one",
    executionContextId: null,
    contextKind: null,
    payloadKind: "unknown",
    plaintextScopeKind: null,
    plaintextBytes: 0,
    resourceRef: null,
    operation: "plugin.bundle.import",
    result: "allowed",
    reasonCode: null,
    scope: {
      workspace_id: "workspace-one",
      document_id: null,
      share_id: null,
    },
    resource: {
      kind: "plugin",
      id: "plugin-one",
      version_hash: null,
    },
    action: {
      operation: "plugin.bundle.import",
      result: "completed",
    },
    sensitivity: "metadata",
    correlation: {
      request_id: "request-one",
      capability_id: "capability-one",
      execution_context_id: null,
      authority_event_ref: null,
    },
    created_at: "2026-06-21T00:00:00.000Z",
    ...overrides,
  } as PluginAuditEvent;
}
