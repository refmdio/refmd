import { createPersistedSignal } from "@/shared/lib/persisted-signal";
const WORKSPACE_STORAGE_KEY = "refmd_workspace_id";
const [currentWorkspaceId, setCurrentWorkspaceId] = createPersistedSignal(WORKSPACE_STORAGE_KEY);
export { currentWorkspaceId, setCurrentWorkspaceId };
