import { Navigate, Route, Router } from "@solidjs/router";
import LoginPage from "@/routes/auth/login";
import RegisterPage from "@/routes/auth/register";
import DeviceRegisterPage from "@/routes/devices/register";
import RecoveryPage from "@/routes/auth/recovery";
import PasswordResetPage from "@/routes/auth/password-reset";
import InvitePage from "@/routes/invite";
import { DashboardRoute } from "@/app/router/DashboardRoute";
import { WorkspaceRoot } from "@/app/workspace/WorkspaceRoot";
import { RequireAuth, RequireGuest } from "@/app/router/AuthGuard";

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
          <Route path={["/dashboard", "/document/:documentId"]} component={DashboardRoute} />
        </Route>
      </Route>
    </Router>
  );
}
