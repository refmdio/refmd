import { lazy } from "solid-js";
import { Navigate, Route, Router } from "@solidjs/router";
import { WorkspaceRoot } from "@/app/workspace/WorkspaceRoot";
import { RequireAuth, RequireGuest } from "@/app/router/AuthGuard";

const LoginPage = lazy(() => import("@/routes/auth/login"));
const RegisterPage = lazy(() => import("@/routes/auth/register"));
const DeviceRegisterPage = lazy(() => import("@/routes/devices/register"));
const RecoveryPage = lazy(() => import("@/routes/auth/recovery"));
const PasswordResetPage = lazy(() => import("@/routes/auth/password-reset"));
const DocumentPage = lazy(() => import("@/routes/document/[documentId]"));
const InvitePage = lazy(() => import("@/routes/invite"));
const DashboardPage = lazy(() => import("@/routes/dashboard"));

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

      <Route path="/" component={RequireAuth}>
        <Route path="/" component={WorkspaceRoot}>
          <Route path="/" component={() => <Navigate href="/dashboard" />} />
          <Route path="/dashboard" component={DashboardPage} />
          <Route path="/document/:documentId" component={DocumentPage} />
        </Route>
      </Route>
    </Router>
  );
}
