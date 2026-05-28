import { lazy, type ParentProps } from "solid-js";
import { Navigate, Route, Router, useLocation, type MatchFilters } from "@solidjs/router";
import { Show } from "solid-js";
import { isPublicPath } from "@/app/bootstrap/session";
import { WorkspaceRoot } from "@/app/workspace/WorkspaceRoot";
import { RequireAuth, RequireGuest } from "@/app/router/AuthGuard";

const LoginPage = lazy(() => import("@/pages/auth/login"));
const RegisterPage = lazy(() => import("@/pages/auth/register"));
const DeviceRegisterPage = lazy(() => import("@/pages/devices/register"));
const RecoveryPage = lazy(() => import("@/pages/auth/recovery"));
const PasswordResetPage = lazy(() => import("@/pages/auth/password-reset"));
const DocumentPage = lazy(() => import("@/pages/document/[documentId]"));
const MountPage = lazy(() => import("@/pages/mounts/[mountId]"));
const PublicAuthorPage = lazy(() => import("@/pages/public/[authorSlug]"));
const PublicDocumentPage = lazy(() => import("@/pages/public/[authorSlug]/[documentSlug]"));
const InvitePage = lazy(() => import("@/pages/invite"));
const DashboardPage = lazy(() => import("@/pages/dashboard"));
const ShareLandingPage = lazy(() => import("@/pages/share/[shareSlug]"));
const ShareDocumentPage = lazy(() => import("@/pages/share/d/[documentToken]"));
const ShareFolderPage = lazy(() => import("@/pages/share/f/[folderToken]"));

const publicAuthorRouteFilters: MatchFilters = {
  authorHandle: /^@[A-Za-z0-9][A-Za-z0-9-]*$/,
};

function WorkspaceRoute(props: ParentProps) {
  const location = useLocation();

  return (
    <Show when={!isPublicPath(location.pathname)}>
      <RequireAuth>
        <WorkspaceRoot>{props.children}</WorkspaceRoot>
      </RequireAuth>
    </Show>
  );
}

function RootRedirect() {
  const location = useLocation();
  return location.pathname === "/" ? <Navigate href="/dashboard" /> : null;
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

      <Route component={WorkspaceRoute}>
        <Route path="/dashboard" component={DashboardPage} />
        <Route path="/document/:documentId" component={DocumentPage} />
        <Route path="/mounts/:mountId" component={MountPage} />
      </Route>
      <Route path="/" component={RootRedirect} />
    </Router>
  );
}
