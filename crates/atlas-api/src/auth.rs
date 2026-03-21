use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, state::AppState};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub subject: String,
    pub tenant_id: String,
    pub project_id: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenClaims {
    sub: String,
    tenant_id: String,
    project_id: String,
    roles: Vec<String>,
    iss: String,
    exp: usize,
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

impl AuthContext {
    pub fn is_admin(&self) -> bool {
        self.roles.iter().any(|r| r.eq_ignore_ascii_case("admin"))
    }

    pub fn can_write(&self) -> bool {
        self.is_admin()
            || self
                .roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case("writer") || r.eq_ignore_ascii_case("write"))
    }

    pub fn can_read(&self) -> bool {
        self.can_write()
            || self
                .roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case("reader") || r.eq_ignore_ascii_case("read"))
    }

    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(ApiError::forbidden("requiere rol admin"))
        }
    }

    pub fn require_write(&self) -> Result<(), ApiError> {
        if self.can_write() {
            Ok(())
        } else {
            Err(ApiError::forbidden("requiere permisos de escritura"))
        }
    }

    pub fn require_read(&self) -> Result<(), ApiError> {
        if self.can_read() {
            Ok(())
        } else {
            Err(ApiError::forbidden("requiere permisos de lectura"))
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = ApiError;

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

pub fn default_limit(state: &AppState, requested: Option<usize>) -> usize {
    requested
        .unwrap_or(state.config.pagination.default_limit)
        .min(state.config.pagination.max_limit)
}

pub fn validate_bootstrap_token(state: &AppState, token: &str) -> Result<(), ApiError> {
    if token == state.config.auth.bootstrap_token {
        Ok(())
    } else {
        Err(ApiError::forbidden("bootstrap token inválido"))
    }
}

pub fn issue_token(
    state: &AppState,
    subject: &str,
    tenant_id: &str,
    project_id: &str,
    role: &str,
) -> Result<String, ApiError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let exp = now + state.config.auth.jwt_expiration_seconds as usize;

    let claims = TokenClaims {
        sub: subject.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id: project_id.to_string(),
        roles: vec![role.to_string()],
        iss: state.config.auth.issuer.clone(),
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.auth.jwt_secret.as_bytes()),
    )
    .map_err(|err| ApiError::internal(err.to_string()))
}
