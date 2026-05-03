export {
  bootstrapShareParticipantSession,
  bootstrapPasswordProtectedShareParticipantSession,
  clearShareParticipantSession,
  ensureShareParticipantDeviceReady,
} from "./lib/session";
export {
  resolveShareLanding,
  resolveShareLandingRoute,
  type ShareLandingRoot,
} from "./lib/landing";
export { resolveSharedDocumentBootstrap } from "./lib/document-bootstrap";
export { resolveShareDocumentRoute } from "./lib/document-route";
export { resolveShareFolderRoute, type ResolvedShareFolderEntry } from "./lib/folder-route";
export { resolveShareTitle, type ShareTitlePayload } from "./lib/title";
export {
  mountPasswordKey,
  resolveMountedShareOpen,
  resolveMountedShareTitle,
  respondShareMountPasswordChallenge,
  type MountedShareParticipantContext,
} from "./lib/mount-route";
export { enterShareRouteSession, leaveShareRouteSession } from "./lib/route-session";
export { ShareManagementDialog } from "./manage";
export {
  SaveShareMountButton,
  ShareLandingPage,
  useSaveShareMount,
  useShareMountLookup,
} from "./view";
