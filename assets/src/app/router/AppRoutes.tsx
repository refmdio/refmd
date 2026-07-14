import { lazy, type ParentProps } from "solid-js";
import { Navigate, Route, Router, useLocation, type MatchFilters } from "@solidjs/router";
import { Show } from "solid-js";
import { isPublicPath } from "@/app/bootstrap/session";
import { RequireAuth, RequireGuest, RequireSecureLogoutComplete } from "@/app/router/AuthGuard";
import { PendingDeviceMonitor } from "@/features/devices";

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
const WorkspaceRoot = lazy(() =>
  import("@/app/workspace/WorkspaceRoot").then((module) => ({ default: module.WorkspaceRoot })),
);

const publicAuthorRouteFilters: MatchFilters = {
  authorHandle: /^@[A-Za-z0-9][A-Za-z0-9-]*$/,
};

function WorkspaceRoute(props: ParentProps) {
  const location = useLocation();

  return (
    <Show when={!isPublicPath(location.pathname)}>
      <RequireAuth>
        <PendingDeviceMonitor>
          <WorkspaceRoot>{props.children}</WorkspaceRoot>
        </PendingDeviceMonitor>
      </RequireAuth>
    </Show>
  );
}

function RootRedirect() {
  const location = useLocation();
  return location.pathname === "/" ? <Navigate href="/dashboard" /> : null;
}

function SecureRegisterRoute() {
  return (
    <RequireSecureLogoutComplete>
      <RegisterPage />
    </RequireSecureLogoutComplete>
  );
}

function SecureRecoveryRoute() {
  return (
    <RequireSecureLogoutComplete>
      <RecoveryPage />
    </RequireSecureLogoutComplete>
  );
}

function SecurePasswordResetRoute() {
  return (
    <RequireSecureLogoutComplete>
      <PasswordResetPage />
    </RequireSecureLogoutComplete>
  );
}

function SecureDeviceRegisterRoute() {
  return (
    <RequireSecureLogoutComplete>
      <DeviceRegisterPage />
    </RequireSecureLogoutComplete>
  );
}

export function AppRoutes() {
  return (
    <Router>
      <Route path="/auth" component={RequireGuest}>
        <Route path="/login" component={LoginPage} />
      </Route>

      <Route path="/auth/register" component={SecureRegisterRoute} />
      <Route path="/auth/recovery" component={SecureRecoveryRoute} />
      <Route path="/auth/password-reset" component={SecurePasswordResetRoute} />
      <Route path="/devices/register" component={SecureDeviceRegisterRoute} />
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
