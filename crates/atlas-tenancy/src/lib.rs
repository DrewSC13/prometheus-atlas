use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Owner,
    Admin,
    Analyst,
    Operator,
    Viewer,
}

impl WorkspaceRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Analyst => "analyst",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    pub fn can_admin(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_write(&self) -> bool {
        matches!(
            self,
            Self::Owner | Self::Admin | Self::Analyst | Self::Operator
        )
    }

    pub fn can_read(&self) -> bool {
        true
    }
}

impl std::str::FromStr for WorkspaceRole {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "analyst" => Ok(Self::Analyst),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            other => Err(format!("workspace role no soportado: {other}")),
        }
    }
}

impl std::fmt::Display for WorkspaceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
}

impl Organization {
    pub fn new(name: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            organization_id: Uuid::new_v4().to_string(),
            name: name.into(),
            slug: slug.into(),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub workspace_id: String,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    pub environment: String,
    pub created_at: DateTime<Utc>,
}

impl Workspace {
    pub fn new(
        organization_id: impl Into<String>,
        name: impl Into<String>,
        slug: impl Into<String>,
        environment: impl Into<String>,
    ) -> Self {
        Self {
            workspace_id: Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            name: name.into(),
            slug: slug.into(),
            environment: environment.into(),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasUser {
    pub user_id: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AtlasUser {
    pub fn new(
        subject: impl Into<String>,
        email: Option<String>,
        display_name: Option<String>,
    ) -> Self {
        Self {
            user_id: Uuid::new_v4().to_string(),
            subject: subject.into(),
            email,
            display_name,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub membership_id: String,
    pub organization_id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub role: WorkspaceRole,
    pub created_at: DateTime<Utc>,
}

impl Membership {
    pub fn new(
        organization_id: impl Into<String>,
        workspace_id: impl Into<String>,
        user_id: impl Into<String>,
        role: WorkspaceRole,
    ) -> Self {
        Self {
            membership_id: Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            workspace_id: workspace_id.into(),
            user_id: user_id.into(),
            role,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenancyScope {
    pub organization_id: String,
    pub workspace_id: String,
}

impl TenancyScope {
    pub fn new(organization_id: impl Into<String>, workspace_id: impl Into<String>) -> Self {
        Self {
            organization_id: organization_id.into(),
            workspace_id: workspace_id.into(),
        }
    }

    pub fn to_legacy_ids(&self) -> (&str, &str) {
        (&self.organization_id, &self.workspace_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_permissions_are_consistent() {
        assert!(WorkspaceRole::Owner.can_admin());
        assert!(WorkspaceRole::Admin.can_write());
        assert!(WorkspaceRole::Viewer.can_read());
        assert!(!WorkspaceRole::Viewer.can_write());
    }

    #[test]
    fn creates_organization_workspace_user_membership() {
        let org = Organization::new("Acme", "acme");
        let ws = Workspace::new(org.organization_id.clone(), "Prod", "prod", "production");
        let user = AtlasUser::new(
            "claudio",
            Some("claudio@example.com".to_string()),
            Some("Claudio".to_string()),
        );
        let membership = Membership::new(
            org.organization_id.clone(),
            ws.workspace_id.clone(),
            user.user_id.clone(),
            WorkspaceRole::Admin,
        );

        assert_eq!(ws.organization_id, org.organization_id);
        assert_eq!(membership.organization_id, org.organization_id);
        assert_eq!(membership.workspace_id, ws.workspace_id);
        assert_eq!(membership.user_id, user.user_id);
    }
}
