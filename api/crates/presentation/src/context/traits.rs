use std::sync::Arc;

use application::core::services::authorization::AuthorizationServiceFacade;
use application::documents::services::sharing::ShareServiceFacade;
use application::identity::services::auth::auth_service::AuthServiceFacade;
use application::identity::services::auth::user_sessions::UserSessionServiceFacade;
use application::workspaces::services::WorkspaceServiceFacade;

pub trait HasAuthServices: Send + Sync {
    fn auth_service(&self) -> Arc<dyn AuthServiceFacade>;
    fn session_service(&self) -> Arc<dyn UserSessionServiceFacade>;
}

pub trait HasWorkspaceService: Send + Sync {
    fn workspace_service(&self) -> Arc<dyn WorkspaceServiceFacade>;
}

pub trait HasShareService: Send + Sync {
    fn share_service(&self) -> Arc<dyn ShareServiceFacade>;
}

pub trait HasAuthorizationService: Send + Sync {
    fn authorization(&self) -> Arc<dyn AuthorizationServiceFacade>;
}
