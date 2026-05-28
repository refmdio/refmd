import { describe, expect, it, vi } from "vitest";
import { createPluginNetworkProxyRequestSigner } from "./proxy-request-signer";

const signPluginNetworkProxyRequest = vi.fn(async () => ({
  transcript: {
    protocol: "refmd.hybrid-signature-transcript",
    signing_purpose: "plugin_network_proxy_request",
  },
  signature: {
    protocol: "refmd.hybrid-signature",
    signing_key_id: "signing-key-one",
    transcript_hash: "transcript-hash-one",
  },
  signing_key_id: "signing-key-one",
  hybrid_signing_public_key_material: {
    protocol: "refmd.hybrid-signing-key-material",
    owner_kind: "device",
    owner_id: "device-one",
    signing_key_id: "signing-key-one",
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    signPluginNetworkProxyRequest,
  }),
}));

describe("createPluginNetworkProxyRequestSigner", () => {
  it("signs proxy request subjects through the production crypto worker surface", async () => {
    const signer = createPluginNetworkProxyRequestSigner();
    const subject = {
      protocol: "refmd.plugin-network-proxy-request-subject" as const,
      version: 1 as const,
      request_id: "request-one",
      proxy: {
        id: "workspace-proxy",
        scope: "workspace",
        origin: "https://proxy.example/refmd",
      },
      target: {
        url: "https://api.github.com/repos/refmdio/refmd/issues",
        method: "GET",
        headers: { accept: "application/json" },
        body_text: "",
      },
      endpoint: {
        id: "github-rest",
        max_request_bytes: 1024,
        max_response_bytes: 2048,
        credential_audience: "api.github.com",
      },
      runtime: {
        workspace_id: "workspace-one",
        plugin_id: "plugin-one",
        package_id: "package-one",
        application_id: "application-one",
        activation_id: "activation-one",
        frame_generation: 1,
        user_id: "user-one",
        device_id: "device-one",
        owner_scope_kind: "workspace",
        consent_epoch: 1,
        capability_grant_id: "capability-grant-one",
        request_id: "request-one",
        credential_handle_used: false,
      },
    };

    await expect(signer.signProxyRequest(subject)).resolves.toMatchObject({
      signing_key_id: "signing-key-one",
      signature: {
        protocol: "refmd.hybrid-signature",
      },
    });
    expect(signPluginNetworkProxyRequest).toHaveBeenCalledWith({ subject });
  });
});
