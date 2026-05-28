import { describe, expect, it } from "vitest";
import type { PluginNetworkEndpointPolicy } from "../network/host-network";
import { createPluginRuntimeNetworkServices } from "./runtime-network";

const ENDPOINT: PluginNetworkEndpointPolicy = {
  id: "github-rest",
  url: "https://api.github.com/repos/refmdio/refmd/issues",
  methods: ["GET"],
  routes: ["proxy"],
  headers: ["accept"],
  bodySchema: "none",
  maxRequestBytes: 1024,
  maxResponseBytes: 2048,
};

describe("createPluginRuntimeNetworkServices", () => {
  it("wires proxy-only endpoint policy from runtime descriptors", async () => {
    const services = createPluginRuntimeNetworkServices({
      networkEndpoints: [ENDPOINT],
    });

    await expect(
      Promise.resolve(services.endpointPolicy({} as never, "github-rest")),
    ).resolves.toEqual(ENDPOINT);
    await expect(
      Promise.resolve(services.endpointPolicy({} as never, "missing")),
    ).resolves.toBeNull();
  });

  it("wires configured proxy registration without installing auto fallback approval", async () => {
    const services = createPluginRuntimeNetworkServices({
      networkEndpoints: [ENDPOINT],
      networkProxyRegistration: {
        id: "workspace-proxy",
        label: "Workspace Proxy",
        origin: "https://proxy.example/refmd",
        scope: "workspace",
        operatorLabel: "Example NetOps",
      },
    });

    await expect(services.proxyRegistration?.({} as never, ENDPOINT)).resolves.toMatchObject({
      id: "workspace-proxy",
      origin: "https://proxy.example/refmd",
    });
    expect("proxyFallbackAllowed" in services).toBe(false);
  });
});
