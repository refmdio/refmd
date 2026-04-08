import type { CryptoError, CryptoResponse } from "../types";
import { CryptoWorkerError } from "./worker-errors";

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

interface RateLimitRetryPolicy {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

export class WorkerTransport {
  private readonly worker: Worker;
  private readonly pending = new Map<string, PendingRequest>();
  private terminated = false;

  constructor() {
    this.worker = new Worker(new URL("../index.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = (event: MessageEvent<CryptoResponse>) => {
      const { id, type, payload } = event.data;
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);

      if (type === "error") {
        const err = payload as CryptoError;
        pending.reject(new CryptoWorkerError(err.code, err.message));
        return;
      }

      pending.resolve(payload);
    };

    this.worker.onerror = (event) => {
      for (const [id, pending] of this.pending) {
        pending.reject(new Error(`Worker error: ${event.message}`));
        this.pending.delete(id);
      }
    };
  }

  async send(type: string, payload: unknown): Promise<unknown> {
    const retryPolicy = this.getRateLimitRetryPolicy(type);

    for (let attempt = 0; ; attempt++) {
      try {
        return await this.sendOnce(type, payload);
      } catch (err) {
        if (
          retryPolicy &&
          err instanceof CryptoWorkerError &&
          err.code === "rate_limited" &&
          attempt < retryPolicy.maxRetries
        ) {
          const backoffMs = Math.min(
            retryPolicy.baseDelayMs * (attempt + 1),
            retryPolicy.maxDelayMs,
          );
          const jitterMs = Math.floor(Math.random() * 50);
          await new Promise((resolve) => setTimeout(resolve, backoffMs + jitterMs));
          continue;
        }

        throw err;
      }
    }
  }

  terminate(): void {
    this.terminated = true;
    for (const [id, pending] of this.pending) {
      pending.reject(new Error("Worker terminated"));
      this.pending.delete(id);
    }
    this.worker.terminate();
  }

  private getRateLimitRetryPolicy(type: string): RateLimitRetryPolicy | null {
    if (type === "derive-auth-keys") {
      return { maxRetries: 2, baseDelayMs: 10_000, maxDelayMs: 10_000 };
    }
    if (type.startsWith("decrypt-")) {
      return { maxRetries: 12, baseDelayMs: 100, maxDelayMs: 1_000 };
    }
    return null;
  }

  private sendOnce(type: string, payload: unknown): Promise<unknown> {
    if (this.terminated) {
      return Promise.reject(new Error("Worker terminated"));
    }

    return new Promise((resolve, reject) => {
      const id = crypto.randomUUID();
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, payload });
    });
  }
}
