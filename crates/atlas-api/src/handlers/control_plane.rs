use std::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    auth::{default_limit, scope_from_auth, AuthContext},
    error::{ApiError, ApiResult},
    models::{
        ApiEnvelope, CreateMembershipRequest, CreateOrganizationRequest, CreateUserRequest,
        CreateWorkspaceRequest, MembershipsResponse, OrganizationsResponse, PaginationMeta,
        UsersResponse, WorkspacesResponse,
    },
    state::AppState,
};

#[derive(Debug, serde::Deserialize)]
pub struct ListParams {
    pub limit: Option<usize>,
}

pub async fn create_organization(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateOrganizationRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_tenancy::Organization>>> {
    auth.require_admin()?;

    let org = atlas_tenancy::Organization {
        organization_id: body
            .organization_id
            .unwrap_or_else(|| format!("org-{}", Uuid::new_v4())),
        name: body.name,
        slug: body.slug,
        created_at: Utc::now(),
    };

    let scope = scope_from_auth(&auth);
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    store.upsert_organization(&org)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "control-plane.organization.create",
        "organization",
        &org.organization_id,
        &serde_json::json!({
            "name": org.name,
            "slug": org.slug
        }),
    )?;

    Ok(Json(ApiEnvelope { data: org }))
}

pub async fn list_organizations(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ListParams>,
) -> ApiResult<Json<OrganizationsResponse>> {
    auth.require_read()?;
    let limit = default_limit(&state, query.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let mut items = store.list_organizations()?;
    items.truncate(limit);

    Ok(Json(OrganizationsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn create_workspace(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateWorkspaceRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_tenancy::Workspace>>> {
    auth.require_admin()?;

    let workspace = atlas_tenancy::Workspace {
        workspace_id: body
            .workspace_id
            .unwrap_or_else(|| format!("ws-{}", Uuid::new_v4())),
        organization_id: body.organization_id,
        name: body.name,
        slug: body.slug,
        environment: body.environment,
        created_at: Utc::now(),
    };

    let scope = scope_from_auth(&auth);
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    store.upsert_workspace(&workspace)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "control-plane.workspace.create",
        "workspace",
        &workspace.workspace_id,
        &serde_json::json!({
            "organization_id": workspace.organization_id,
            "name": workspace.name,
            "slug": workspace.slug,
            "environment": workspace.environment
        }),
    )?;

    Ok(Json(ApiEnvelope { data: workspace }))
}

pub async fn list_workspaces_by_organization(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Path(organization_id): Path<String>,
    Query(query): Query<ListParams>,
) -> ApiResult<Json<WorkspacesResponse>> {
    auth.require_read()?;
    let limit = default_limit(&state, query.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let mut items = store.list_workspaces_by_org(&organization_id)?;
    items.truncate(limit);

    Ok(Json(WorkspacesResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateUserRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_tenancy::AtlasUser>>> {
    auth.require_admin()?;

    let user = atlas_tenancy::AtlasUser {
        user_id: body
            .user_id
            .unwrap_or_else(|| format!("usr-{}", Uuid::new_v4())),
        subject: body.subject,
        email: body.email,
        display_name: body.display_name,
        created_at: Utc::now(),
    };

    let scope = scope_from_auth(&auth);
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    store.upsert_user(&user)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "control-plane.user.create",
        "user",
        &user.user_id,
        &serde_json::json!({
            "subject": user.subject,
            "email": user.email,
            "display_name": user.display_name
        }),
    )?;

    Ok(Json(ApiEnvelope { data: user }))
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ListParams>,
) -> ApiResult<Json<UsersResponse>> {
    auth.require_read()?;
    let limit = default_limit(&state, query.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let mut items = store.list_users()?;
    items.truncate(limit);

    Ok(Json(UsersResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}

pub async fn create_membership(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Json(body): Json<CreateMembershipRequest>,
) -> ApiResult<Json<ApiEnvelope<atlas_tenancy::Membership>>> {
    auth.require_admin()?;

    let role = atlas_tenancy::WorkspaceRole::from_str(&body.role)
        .map_err(|err| ApiError::bad_request(format!("role inválido: {err}")))?;

    let membership = atlas_tenancy::Membership {
        membership_id: body
            .membership_id
            .unwrap_or_else(|| format!("mship-{}", Uuid::new_v4())),
        organization_id: body.organization_id,
        workspace_id: body.workspace_id,
        user_id: body.user_id,
        role,
        created_at: Utc::now(),
    };

    let scope = scope_from_auth(&auth);
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    store.upsert_membership(&membership)?;
    store.record_audit_event_scoped(
        &scope,
        &auth.subject,
        "control-plane.membership.create",
        "membership",
        &membership.membership_id,
        &serde_json::json!({
            "organization_id": membership.organization_id,
            "workspace_id": membership.workspace_id,
            "user_id": membership.user_id,
            "role": membership.role.to_string()
        }),
    )?;

    Ok(Json(ApiEnvelope { data: membership }))
}

pub async fn list_memberships(
    State(state): State<Arc<AppState>>,
    auth: AuthContext,
    Query(query): Query<ListParams>,
) -> ApiResult<Json<MembershipsResponse>> {
    auth.require_read()?;
    let scope = scope_from_auth(&auth);
    let limit = default_limit(&state, query.limit);

    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock"))?;
    let mut items = store.list_memberships_scoped(&scope)?;
    items.truncate(limit);

    Ok(Json(MembershipsResponse {
        data: items.clone(),
        pagination: PaginationMeta {
            limit,
            returned: items.len(),
        },
    }))
}
