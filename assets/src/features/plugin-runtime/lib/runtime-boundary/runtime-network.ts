import {
  createDefaultPluginHostNetworkServices,
  type PluginHostNetworkServices,
  type PluginNetworkEndpointPolicy,
  type PluginNetworkProxyRegistration,
  type PluginNetworkProxyRequestSigner,
} from "../network/host-network";

export function createPluginRuntimeNetworkServices(options: {
  networkEndpoints?: readonly PluginNetworkEndpointPolicy[];
  networkProxyRegistration?: PluginNetworkProxyRegistration | null;
  networkProxyRequestSigner?: PluginNetworkProxyRequestSigner | null;
}): PluginHostNetworkServices {
  const defaults = createDefaultPluginHostNetworkServices({
    proxyRegistration: options.networkProxyRegistration,
    requestSigner: options.networkProxyRequestSigner,
  });
  const endpoints = new Map(
    (options.networkEndpoints ?? []).map((endpoint) => [endpoint.id, endpoint]),
  );

  return {
    ...defaults,
    endpointPolicy(_context, endpointId) {
      return endpoints.get(endpointId) ?? null;
    },
  };
}
