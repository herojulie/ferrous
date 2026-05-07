use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap};
use std::io::Write;
use std::time::Instant;
use reqwest::Client;
use tokio::process::Command;
use tempfile::NamedTempFile;
use crate::config::{load_config, save_config, Auth0Config};
use crate::token::TokenManager;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------
#[derive(Clone)]
pub struct AppState {
    pub token_manager: TokenManager,
    pub http: Client,
}

// ---------------------------------------------------------------------------
// GET /api/token-status
// Returns cache status for every profile that has a cached token.
// ---------------------------------------------------------------------------
pub async fn token_status(State(state): State<AppState>) -> Json<Value> {
    let all = state.token_manager.all_status().await;
    Json(json!(all))
}

// ---------------------------------------------------------------------------
// POST /api/token/refresh/:profile
// Force-refresh the token for one profile (or all if profile == "_all").
// ---------------------------------------------------------------------------
pub async fn token_refresh(
    State(state): State<AppState>,
    axum::extract::Path(profile): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if profile == "_all" {
        state.token_manager.invalidate(None).await;
        return Ok(Json(json!({ "ok": true, "refreshed": "_all" })));
    }

    state.token_manager.invalidate(Some(&profile)).await;
    match state.token_manager.get_token(&profile).await {
        Ok(_) => {
            let secs = state.token_manager.remaining_secs(&profile).await.unwrap_or(0);
            Ok(Json(json!({ "ok": true, "profile": profile, "expires_in_seconds": secs})))
        }
        Err(e) => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({ "detail": e.to_string() })),
        )),
    }
}

// ---------------------------------------------------------------------------
// GET /api/profiles
// List all configured profiles (secrets masked).
// ---------------------------------------------------------------------------
pub async fn get_profiles() -> Json<Value> {
    let cfg = load_config();
    let profiles: HashMap<String, Value> = cfg.profiles.iter().map(|(name, a)| {
        (name.clone(), json!({
            "domain": a.domain,
            "client_id": a.client_id,
            "client_secret": if a.client_secret.is_empty() { "" } else { "********" },
            "audience": a.audience,
        }))
    }).collect();
    Json(json!(profiles))
}

// ---------------------------------------------------------------------------
// PUT /api/profiles/:name
// Create or update a single profile.
// ---------------------------------------------------------------------------
pub async fn upsert_profile(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(payload): Json<Auth0Config>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut cfg = load_config();
    cfg.profiles.insert(name.clone(), payload);
    save_config(&cfg).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    // Invalidate any cached token so the new credentials are used next time.
    state.token_manager.invalidate(Some(&name)).await;
    Ok(Json(json!({ "ok": true, "profile": name })))
}

// ---------------------------------------------------------------------------
// DELETE /api/profiles/:name
// Remove a profile.
// ---------------------------------------------------------------------------
pub async fn delete_profile(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut cfg = load_config();
    if cfg.profiles.remove(&name).is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "detail": format!("Profile '{}' not found", name) })),
        ));
    }
    save_config(&cfg).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    state.token_manager.invalidate(Some(&name)).await;
    Ok(Json(json!({ "ok": true, "profile": name })))
}

// ---------------------------------------------------------------------------
// POST /api/call
// Proxy an HTTP request; optionally attach a Bearer token from a named profile.
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct ApiRequest {
    method: String,
    url: String,
    #[serde(default)]
    headers: HashMap<String ,String>,
    body: Option<Value>,
    /// Name of the Auth0 profile to use for the Bearer token.
    /// Set to null / omit to skip authentication.
    profile: Option<String>,
}

#[derive(Serialize)]
pub struct ApiResponse {
    status: u16,
    elapsed_ms: u128,
    headers: HashMap<String, String>,
    body: Value,
}

pub async fn proxy_call(
    State(state): State<AppState>,
    Json(req): Json<ApiRequest>,
) -> Result<Json<ApiResponse>, (StatusCode, Json<Value>)> {
    let mut builder = match req.method.to_uppercase().as_str() {
        "GET" => state.http.get(&req.url),
        "POST" => state.http.post(&req.url),
        "PUT" => state.http.put(&req.url),
        "PATCH" => state.http.patch(&req.url),
        "DELETE" => state.http.delete(&req.url),
        m => return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "detail": format!("Unknown method: {}", m) })),
        )),
    };

    for (k, v) in &req.headers {
        builder = builder.header(k, v);
    }

    // Attach Bearer token when a profile is specified.
    if let Some(ref profile) = req.profile {
        let token = state.token_manager.get_token(profile).await.map_err(|e| (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "detail": e.to_string() })),
        ))?;
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }

    if let Some(body) = req.body {
        builder = builder.json(&body);
    }

    let start = Instant::now();
    let res = builder.send().await.map_err(|e| (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    let elapsed_ms = start.elapsed().as_millis();

    let status = res.status().as_u16();
    let headers: HashMap<String, String> = res.headers().iter()
    .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
    .collect();

    let body: Value = res.json().await
    .unwrap_or(Value::String("(non-JSON response)".into()));

    Ok(Json(ApiResponse { status, elapsed_ms, headers, body}))
}

// ---------------------------------------------------------------------------
// Saved requests
// ---------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone)]
pub struct SavedRequest {
    pub name: String,
    pub request: Value,
}

pub async fn get_saved() -> Json<Value> {
    let cfg = load_config();
    Json(Value::Array(cfg.saved_requests))
}

pub async fn post_saved(
    Json(payload): Json<SavedRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut cfg = load_config();
    cfg.saved_requests.retain(|s| {
        s.get("name").and_then(|n| n.as_str()) != Some(&payload.name)
    });
    cfg.saved_requests.push(json!({ "name": payload.name, "request": payload.request }));
    save_config(&cfg).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_saved(
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut cfg = load_config();
    cfg.saved_requests.retain(|s| {
        s.get("name").and_then(|n| n.as_str()) != Some(&name)
    });
    save_config(&cfg).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// GET /api/vault/status
// Check vault password configuration
// ---------------------------------------------------------------------------
pub async fn vault_status() -> Json<Value> {
    let cfg = load_config();
    Json(json!({ "configured": cfg.vault_password.is_some() }))
}

// ---------------------------------------------------------------------------
// POST /api/vault/password
// Save vault password
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct VaultPasswordPayload {
    password: String,
}

pub async fn save_vault_password(
    Json(payload): Json<VaultPasswordPayload>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut cfg = load_config();
    cfg.vault_password = Some(payload.password);
    save_config(&cfg).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// POST /api/vault/decrypt
// Decrypt ansible variable
// ---------------------------------------------------------------------------
#[derive(Deserialize)]
pub struct VaultDecryptPayload {
    ciphertext: String,
}

pub async fn vault_decrypt(
    Json(payload): Json<VaultDecryptPayload>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let cfg = load_config();
    let password = cfg.vault_password.ok_or_else(|| (
        StatusCode::BAD_REQUEST,
        Json(json!({ "detail": "Vault password not configured" })),
    ))?;

    // Write password to a temp file
    let mut pw_file = NamedTempFile::new().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;
    pw_file.write_all(password.as_bytes()).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;

    // Write ciphertext to a temp file
    // Strip variable name prefix (e.g. "my_var: !vault |") and leading whitespace per line
    let cleaned: String = payload.ciphertext
    .lines()
    .map(|l| l.trim())
    .filter(|l| !l.is_empty() && !l.contains("!vault"))
    .collect::<Vec<_>>()
    .join("\n");

    let mut ct_file = NamedTempFile::new().map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),    
    ))?;
    ct_file.write_all(cleaned.as_bytes()).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": e.to_string() })),
    ))?;

    let output = Command::new("ansible-vault")
    .args([
        "decrypt",
        "--vault-password-file", pw_file.path().to_str().unwrap(),
        "--output", "-",    // print to stdout instead of overwriting file
        ct_file.path().to_str().unwrap(),
    ])
    .output()
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "detail": format!("Failed to run ansible-vaule: {}", e) })),
    ))?;

    if output.status.success() {
        let plaintext = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(Json(json!({ "ok": true, "plaintext": plaintext })))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "detail": stderr })),
        ))
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
pub fn router() -> Router<AppState> {
    Router::new()
    .route("/api/token-status", get(token_status))
    .route("/api/token/refresh/:profile", post(token_refresh))
    .route("/api/profiles", get(get_profiles))
    .route("/api/profiles/:name", axum::routing::put(upsert_profile).delete(delete_profile))
    .route("/api/call", post(proxy_call))
    .route("/api/saved", get(get_saved).post(post_saved))
    .route("/api/saved/:name", delete(delete_saved))
    .route("/api/vault/status", get(vault_status))
    .route("/api/vault/password", post(save_vault_password))
    .route("/api/vault/decrypt", post(vault_decrypt))
}