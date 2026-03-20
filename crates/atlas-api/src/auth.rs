use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub subject: String,
    pub tenant_id: String,
    pub project_id: String,
    pub roles: Vec<String>,
}

impl Default for AuthContext {
    fn default() -> Self {
        Self {
            subject: "local-dev".to_string(),
            tenant_id: "default".to_string(),
            project_id: "default".to_string(),
            roles: vec!["admin".to_string()],
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let tenant_id = parts
            .headers
            .get("x-tenant-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("default")
            .to_string();

        let project_id = parts
            .headers
            .get("x-project-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("default")
            .to_string();

        let subject = parts
            .headers
            .get("x-subject")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("local-dev")
            .to_string();

        let roles = parts
            .headers
            .get("x-roles")
            .and_then(|v| v.to_str().ok())
            .map(|raw| {
                raw.split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|items| !items.is_empty())
            .unwrap_or_else(|| vec!["admin".to_string()]);

        Ok(Self {
            subject,
            tenant_id,
            project_id,
            roles,
        })
    }
}

pub fn scope_from_auth(auth: &AuthContext) -> atlas_store::StorageScope {
    atlas_store::StorageScope::new(auth.tenant_id.clone(), auth.project_id.clone())
}
