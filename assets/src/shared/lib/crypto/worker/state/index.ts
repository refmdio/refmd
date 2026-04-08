export type { WorkerKeyState } from "./shared";
export { zeroOut } from "./shared";
export { createInitialState, clearState } from "./lifecycle";
export {
  evictCachedDek,
  getCachedDek,
  getCachedKek,
  setActiveDekVersion,
  setActiveKekVersion,
  setCachedDek,
  setCachedKek,
} from "./cache";
