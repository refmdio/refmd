import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type {
  PluginNetworkProxyRequestSigner,
  PluginNetworkProxyRequestSubject,
} from "../network/host-network";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";

export function createPluginNetworkProxyRequestSigner(): PluginNetworkProxyRequestSigner {
  return {
    async signProxyRequest(subject: PluginNetworkProxyRequestSubject) {
      const signed = await getCryptoWorker().signPluginNetworkProxyRequest({
        subject: subject as unknown as Record<string, StrictJsonValue>,
      });
      return {
        transcript: signed.transcript as Record<string, unknown>,
        signature: signed.signature as unknown as Record<string, unknown>,
        signing_key_id: signed.signing_key_id,
        hybrid_signing_public_key_material:
          signed.hybrid_signing_public_key_material as unknown as Record<string, unknown>,
      };
    },
  };
}
