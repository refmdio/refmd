import { describe, expect, it } from "vite-plus/test";
import { derivePluginManifestAuthority } from "./manifest-authority";

describe("plugin manifest authority", () => {
  it("rejects manifest permissions outside the Host-enforceable grammar", () => {
    expect(() =>
      derivePluginManifestAuthority({
        id: "com.example.invalid",
        version: "1.0.0",
        permissions: ["document:read", "storage:read", "plugin:admin"],
        network: { endpoints: [] },
        rendererSlots: [],
        documentScopes: [],
      }),
    ).toThrow("plugin_manifest_permission_invalid");
  });

  it("rejects typed inline renderer permissions without an inline document type", () => {
    expect(() =>
      derivePluginManifestAuthority({
        id: "com.example.inline",
        version: "1.0.0",
        permissions: ["plaintext:render:inline:badge"],
        network: { endpoints: [] },
        rendererSlots: [{ kind: "inline", type: "badge" }],
        documentScopes: [],
      }),
    ).toThrow("plugin_manifest_permission_invalid");
  });

  it("accepts current Host-enforceable manifest permissions", () => {
    const authority = derivePluginManifestAuthority({
      id: "com.example.valid",
      version: "1.0.0",
      permissions: [
        "document:read:active",
        "document:write",
        "storage:read:userLocal",
        "storage:write:cache",
        "credential:use",
        "network:fetch",
        "editor:selection:read",
        "editor:context:read",
        "plaintext:render:block:chart",
        "plaintext:render:inline:code",
        "ui:command",
      ],
      network: { endpoints: [] },
      rendererSlots: [],
      documentScopes: [],
    });

    expect(authority.permissions).toContain("document:read:active");
    expect(authority.permissions).toContain("plaintext:render:block:chart");
    expect(authority.permissions).toContain("plaintext:render:inline:code");
    expect(authority.permissions).toContain("ui:command");
    expect(authority.highRiskConsents).toEqual([
      "plaintext_document_write",
      "plaintext_network_egress",
      "plaintext_cache_storage",
    ]);
  });

  it("accepts proxy-only endpoint authority", () => {
    const authority = derivePluginManifestAuthority({
      id: "com.example.network",
      version: "1.0.0",
      permissions: ["network:fetch"],
      network: {
        endpoints: [
          {
            id: "api",
            url: "https://api.example.com/export",
            methods: ["POST"],
            routes: ["proxy"],
            allowedHeaders: ["accept"],
            bodySchema: "json",
          },
        ],
      },
      rendererSlots: [],
      documentScopes: [],
    });

    expect(authority.networkEndpoints[0]?.routes).toEqual(["proxy"]);
  });

  it("rejects non-proxy endpoint routes instead of silently normalizing them", () => {
    for (const routes of [
      ["direct"],
      ["auto"],
      ["extension"],
      ["direct", "proxy"],
      ["proxy", "extension"],
      ["unknown"],
      [],
      undefined,
    ]) {
      expect(() =>
        derivePluginManifestAuthority({
          id: "com.example.network",
          version: "1.0.0",
          permissions: ["network:fetch"],
          network: {
            endpoints: [
              {
                id: "api",
                url: "https://api.example.com/export",
                methods: ["POST"],
                ...(routes === undefined ? {} : { routes }),
              },
            ],
          },
          rendererSlots: [],
          documentScopes: [],
        }),
      ).toThrow("plugin_manifest_network_route_invalid");
    }
  });
});
