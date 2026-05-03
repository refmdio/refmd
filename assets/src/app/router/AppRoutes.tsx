import { lazy, type ParentProps } from "solid-js";
import { Navigate, Route, Router, type MatchFilters } from "@solidjs/router";
import { WorkspaceRoot } from "@/app/workspace/WorkspaceRoot";
import { RequireAuth, RequireGuest } from "@/app/router/AuthGuard";

const LoginPage = lazy(() => import("@/routes/auth/login"));
const RegisterPage = lazy(() => import("@/routes/auth/register"));
const DeviceRegisterPage = lazy(() => import("@/routes/devices/register"));
const RecoveryPage = lazy(() => import("@/routes/auth/recovery"));
const PasswordResetPage = lazy(() => import("@/routes/auth/password-reset"));
const DocumentPage = lazy(() => import("@/routes/document/[documentId]"));
const ShareLandingPage = lazy(() => import("@/routes/share/[shareSlug]"));
const ShareDocumentPage = lazy(() => import("@/routes/share/d/[documentToken]"));
const ShareFolderPage = lazy(() => import("@/routes/share/f/[folderToken]"));
const MountPage = lazy(() => import("@/routes/mounts/[mountId]"));
const PublicAuthorPage = lazy(() => import("@/routes/public/[authorSlug]"));
const PublicDocumentPage = lazy(() => import("@/routes/public/[authorSlug]/[documentSlug]"));
const InvitePage = lazy(() => import("@/routes/invite"));
const DashboardPage = lazy(() => import("@/routes/dashboard"));

const publicAuthorRouteFilters: MatchFilters = {
  authorHandle: /^@[A-Za-z0-9][A-Za-z0-9-]*$/,
};

function WorkspaceRoute(props: ParentProps) {
  return (
    <RequireAuth>
      <WorkspaceRoot>{props.children}</WorkspaceRoot>
    </RequireAuth>
  );
}

export function AppRoutes() {
  return (
    <Router>
      <Route path="/auth" component={RequireGuest}>
        <Route path="/login" component={LoginPage} />
      </Route>

      <Route path="/auth/register" component={RegisterPage} />
      <Route path="/auth/recovery" component={RecoveryPage} />
      <Route path="/auth/password-reset" component={PasswordResetPage} />
      <Route path="/devices/register" component={DeviceRegisterPage} />
      <Route path="/invite" component={InvitePage} />
      <Route path="/share/d/:documentToken" component={ShareDocumentPage} />
      <Route path="/share/f/:folderToken" component={ShareFolderPage} />
      <Route path="/share/:shareSlug" component={ShareLandingPage} />
      <Route
        path="/:authorHandle"
        component={PublicAuthorPage}
        matchFilters={publicAuthorRouteFilters}
      />
      <Route
        path="/:authorHandle/:documentSlug"
        component={PublicDocumentPage}
        matchFilters={publicAuthorRouteFilters}
      />

      <Route path="/" component={WorkspaceRoute}>
        <Route path="/" component={() => <Navigate href="/dashboard" />} />
        <Route path="/dashboard" component={DashboardPage} />
        <Route path="/document/:documentId" component={DocumentPage} />
        <Route path="/mounts/:mountId" component={MountPage} />
      </Route>
    </Router>
  );
}
