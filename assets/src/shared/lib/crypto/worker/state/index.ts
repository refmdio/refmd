export type { HybridSigningState, WorkerKeyState } from "./shared";
export { zeroOut } from "./shared";
export { createInitialState, clearState } from "./lifecycle";
export {
  evictCachedKek,
  evictCachedDek,
  getCachedDek,
  getCachedKek,
  setActiveDekVersion,
  setActiveKekVersion,
  setCachedDek,
  setCachedKek,
} from "./cache";
