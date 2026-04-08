export interface TitleDecryptItem {
  documentId: string;
  keyVersion: number;
  encrypted: Uint8Array;
  nonce: Uint8Array;
}

export interface TitleDecryptResult {
  documentId: string;
  title: string | null;
}
