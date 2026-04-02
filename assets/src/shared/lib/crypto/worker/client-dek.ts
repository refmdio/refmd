import type { TitleDecryptItem, TitleDecryptResult } from "./types";
import type { CryptoWorkerClientMethodContext } from "./client-shared";

export interface DekWorkerClientMethods {
  generateDek(
    documentId: string,
    workspaceId: string,
    dekKeyVersion?: number,
    setActive?: boolean,
  ): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array; keyVersion: number }>;
  wrapDek(params: {
    documentId: string;
    workspaceId: string;
  }): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array }>;
  unwrapDek(params: {
    encryptedDek: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    workspaceId: string;
    keyVersion: number;
    isActive?: boolean;
    kekVersion?: number;
  }): Promise<void>;
  encryptTitle(params: {
    title: string;
    documentId: string;
    keyVersion: number;
  }): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  decryptTitle(params: {
    encrypted: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<string>;
  decryptTitleBatch(items: TitleDecryptItem[]): Promise<TitleDecryptResult[]>;
  encryptContent(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptContent(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array>;
  encryptSnapshot(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptSnapshot(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array>;
  hasDek(documentId: string, keyVersion?: number): Promise<boolean>;
  cacheDek(params: { documentId: string; dek: Uint8Array; keyVersion: number }): Promise<void>;
  evictDek(documentId: string, keyVersion: number): Promise<void>;
  encryptOfflineCache(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptOfflineCache(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array>;
  encryptOfflinePending(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  decryptOfflinePending(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array>;
  wrapDekForOffline(params: {
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }>;
  unwrapDekFromOffline(params: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    documentId: string;
    keyVersion: number;
    isActive?: boolean;
  }): Promise<void>;
}

export const dekWorkerClientMethods: DekWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async generateDek(documentId, workspaceId, dekKeyVersion, setActive) {
    return (await this.send("generate-dek", {
      documentId,
      workspaceId,
      dekKeyVersion,
      setActive,
    })) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
      keyVersion: number;
    };
  },

  async wrapDek(params) {
    return (await this.send("wrap-dek", params)) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async unwrapDek(params) {
    await this.send("unwrap-dek", params);
  },

  async encryptTitle(params) {
    return (await this.send("encrypt-title", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptTitle(params) {
    const result = (await this.send("decrypt-title", params)) as { title: string };
    return result.title;
  },

  async decryptTitleBatch(items) {
    return (await this.send("decrypt-title-batch", { items })) as TitleDecryptResult[];
  },

  async encryptContent(params) {
    return (await this.send("encrypt-content", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptContent(params) {
    const result = (await this.send("decrypt-content", params)) as { plaintext: Uint8Array };
    return result.plaintext;
  },

  async encryptSnapshot(params) {
    return (await this.send("encrypt-snapshot", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptSnapshot(params) {
    const result = (await this.send("decrypt-snapshot", params)) as { plaintext: Uint8Array };
    return result.plaintext;
  },

  async hasDek(documentId, keyVersion) {
    const result = (await this.send("has-dek", { documentId, keyVersion })) as {
      hasDek: boolean;
    };
    return result.hasDek;
  },

  async cacheDek(params) {
    await this.send("cache-dek", params);
  },

  async evictDek(documentId, keyVersion) {
    await this.send("evict-dek", { documentId, keyVersion });
  },

  async encryptOfflineCache(params) {
    return (await this.send("encrypt-offline-cache", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptOfflineCache(params) {
    const result = (await this.send("decrypt-offline-cache", params)) as {
      plaintext: Uint8Array;
    };
    return result.plaintext;
  },

  async encryptOfflinePending(params) {
    return (await this.send("encrypt-offline-pending", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptOfflinePending(params) {
    const result = (await this.send("decrypt-offline-pending", params)) as {
      plaintext: Uint8Array;
    };
    return result.plaintext;
  },

  async wrapDekForOffline(params) {
    return (await this.send("wrap-dek-for-offline", params)) as {
      ciphertext: ArrayBuffer;
      iv: ArrayBuffer;
    };
  },

  async unwrapDekFromOffline(params) {
    await this.send("unwrap-dek-from-offline", params);
  },
};
