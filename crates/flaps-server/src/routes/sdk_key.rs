//! Admin handlers for SDK key management within a project/environment scope.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use flaps_domain::{EnvironmentKey, ProjectKey, SdkKeyKind};
use flaps_store::{NewSdkKey, SdkKeyRecord, SdkKeyScope};
use serde::{Deserialize, Serialize};

use crate::{
    auth::AdminPrincipal,
    error::ApiError,
    state::{AppState, Store},
};

/// Path parameters shared by all SDK key routes.
type SdkKeyPath = (String, String);

/// Path parameters for single-key routes.
type SdkKeyItemPath = (String, String, String);

/// Request body for `POST .../keys`.
#[derive(Debug, Deserialize)]
pub struct CreateSdkKeyRequest {
    /// Server or client SDK kind.
    pub kind: SdkKeyKind,
}

/// Response body for `POST .../keys` (includes the raw secret, returned once).
#[derive(Debug, Serialize)]
pub struct CreateSdkKeyResponse {
    /// The raw SDK key. Only returned on creation; store never exposes it again.
    pub secret: String,
    /// Secret-free persisted record.
    pub record: SdkKeyRecord,
}

/// `POST /projects/{project}/environments/{env}/keys`
pub async fn post_sdk_key<S: Store>(
    State(state): State<AppState<S>>,
    principal: AdminPrincipal,
    Path((project_str, env_str)): Path<SdkKeyPath>,
    Json(body): Json<CreateSdkKeyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let project = ProjectKey::new(project_str).map_err(|e| ApiError::InvalidBody(e.to_string()))?;
    let environment =
        EnvironmentKey::new(env_str).map_err(|e| ApiError::InvalidBody(e.to_string()))?;

    // Both parents of the scope must exist. Checking explicitly up front (rather
    // than relying on the foreign-key violation the write would eventually
    // raise) gives a clean 404 for a key requested against a missing scope.
    state
        .store
        .get_project(&project)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;
    state
        .store
        .get_environment(&project, &environment)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;

    // Generate a raw key: prefix (kind letter) + 24 random bytes as hex.
    let raw_key = generate_sdk_key(body.kind).map_err(|e| ApiError::Internal(e.to_string()))?;

    let new_key = NewSdkKey {
        kind: body.kind,
        scope: SdkKeyScope {
            project_key: project,
            environment_key: environment,
        },
    };

    let record = state
        .store
        .create_sdk_key(&principal.username, &raw_key, &new_key)
        .await
        .map_err(ApiError::from)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateSdkKeyResponse {
            secret: raw_key,
            record,
        }),
    ))
}

/// `GET /projects/{project}/environments/{env}/keys`
pub async fn list_sdk_keys<S: Store>(
    State(state): State<AppState<S>>,
    _principal: AdminPrincipal,
    Path((project_str, env_str)): Path<SdkKeyPath>,
) -> Result<Json<Vec<SdkKeyRecord>>, ApiError> {
    let project = ProjectKey::new(project_str).map_err(|e| ApiError::InvalidBody(e.to_string()))?;
    let environment =
        EnvironmentKey::new(env_str).map_err(|e| ApiError::InvalidBody(e.to_string()))?;

    // Both parents of the scope must exist; a missing scope has no keys to list.
    state
        .store
        .get_project(&project)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;
    state
        .store
        .get_environment(&project, &environment)
        .await
        .map_err(ApiError::from)?
        .ok_or(ApiError::NotFound)?;

    let scope = SdkKeyScope {
        project_key: project,
        environment_key: environment,
    };

    let records = state
        .store
        .list_sdk_keys("", &scope)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(records))
}

/// `DELETE /projects/{project}/environments/{env}/keys/{prefix}`
pub async fn delete_sdk_key<S: Store>(
    State(state): State<AppState<S>>,
    principal: AdminPrincipal,
    Path((project_str, env_str, prefix)): Path<SdkKeyItemPath>,
) -> Result<StatusCode, ApiError> {
    let project = ProjectKey::new(project_str).map_err(|e| ApiError::InvalidBody(e.to_string()))?;
    let environment =
        EnvironmentKey::new(env_str).map_err(|e| ApiError::InvalidBody(e.to_string()))?;

    state
        .store
        .revoke_sdk_key(&principal.username, &project, &environment, &prefix)
        .await
        .map_err(ApiError::from)?;

    Ok(StatusCode::NO_CONTENT)
}

/// Generates a raw SDK key with a kind-specific prefix string.
///
/// # Errors
/// Returns an error if the operating system's randomness source cannot be
/// read. Fails closed rather than falling back to a predictable key.
fn generate_sdk_key(kind: SdkKeyKind) -> Result<String, getrandom::Error> {
    let prefix = match kind {
        SdkKeyKind::Server => "sv",
        SdkKeyKind::Client => "cl",
    };
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes)?;
    let hex: String = bytes.iter().fold(String::with_capacity(48), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    Ok(format!("{prefix}_{hex}"))
}

#[cfg(test)]
mod tests {
    use super::generate_sdk_key;
    use flaps_domain::SdkKeyKind;

    #[test]
    fn generated_server_key_has_expected_prefix_and_length() {
        let key = generate_sdk_key(SdkKeyKind::Server).expect("test RNG must be available");
        assert!(key.starts_with("sv_"), "got {key}");
        // "sv_" (3) + 24 bytes as hex (48) = 51 characters.
        assert_eq!(key.len(), 51, "unexpected key length: {key}");
    }

    #[test]
    fn generated_client_key_has_expected_prefix_and_length() {
        let key = generate_sdk_key(SdkKeyKind::Client).expect("test RNG must be available");
        assert!(key.starts_with("cl_"), "got {key}");
        assert_eq!(key.len(), 51, "unexpected key length: {key}");
    }

    #[test]
    fn generated_key_suffix_is_lowercase_hex() {
        let key = generate_sdk_key(SdkKeyKind::Server).expect("test RNG must be available");
        let suffix = key.strip_prefix("sv_").expect("server prefix");
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "suffix must be lowercase hex; got {suffix}"
        );
    }

    #[test]
    fn two_generated_keys_differ() {
        let first = generate_sdk_key(SdkKeyKind::Server).expect("test RNG must be available");
        let second = generate_sdk_key(SdkKeyKind::Server).expect("test RNG must be available");
        assert_ne!(first, second, "salt must be drawn fresh for every key");
    }
}
