export interface KdfParams {
  algorithm: string;
  memory: number;
  iterations: number;
  parallelism: number;
  hash_length: number;
}

export const TARGET_KDF_PARAMS: KdfParams = {
  algorithm: "argon2id",
  memory: 65536,
  iterations: 3,
  parallelism: 4,
  hash_length: 32,
};
