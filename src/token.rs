use crate::config::load_config;
use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug)]
struct TokenCache {
    access_token: String,
    expires_at: Instant,
}

/// Manages Auth0 client-credentials token, one cache entry per named profile.
#[derive(Clone)]
pub struct TokenManager {
    /// profile_name -> cached token
    caches: Arc<Mutex<HashMap<String, TokenCache>>>,
    http: Client,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl TokenManager {
    pub fn new() -> Self {
        Self {
            caches: Arc::new(Mutex::new(HashMap::new())),
            http: Client::new(),
        }
    }

    /// Invalidate the cached token for a specific profile.
    /// If `profile` is None, all profiles are invalidated.
    pub async fn invalidate(&self, profile: Option<&str>) {
        let mut map = self.caches.lock().await;
        match profile {
            Some(name) => { map.remove(name); }
            None => { map.clear(); }
        }
    }

    /// Return a valid Bearer token for the given profile, fetching a new one if necessary.
    pub async fn get_token(&self, profile: &str) -> Result<String> {
        let mut map = self.caches.lock().await;

        if let Some(c) = map.get(profile) {
            if Instant::now() + Duration::from_secs(60) < c.expires_at {
                return Ok(c.access_token.clone());
            }
        }

        let cfg = load_config();
        let auth0 = cfg
            .profiles
            .get(profile)
            .ok_or_else(|| anyhow!("Profile `{}` not found", profile))?
            .clone();

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &auth0.client_id.as_str()),
            ("client_secret", &auth0.client_secret.as_str()),
            ("audience", &auth0.audience.as_str()),
        ];

        let url = format!("https://{}/oauth/token", auth0.domain);
        let res = self.http.post(&url).form(&params).send().await?;

        if !res.status().is_success() {
            let text = res.text().await?;
            return Err(anyhow!("Auth0 error (profile `{}`): {}", profile, text));
        }

        let token_res: TokenResponse = res.json().await?;
        let expires_at = Instant::now() + Duration::from_secs(token_res.expires_in);

        map.insert(profile.to_string(), TokenCache {
            access_token: token_res.access_token.clone(),
            expires_at,
        });

        Ok(token_res.access_token)
    }

    /// Return seconds remaining for a cached token, or None if not cached.
    pub async fn remaining_secs(&self, profile: &str) -> Option<u64> {
        let map = self.caches.lock().await;
        map.get(profile).map(|c| {
            let now = Instant::now();
            if c.expires_at > now { (c.expires_at - now).as_secs() } else { 0 }          
        })
    }

    /// Summarise cache status for all known profiles.
    pub async fn all_status(&self) -> HashMap<String, u64> {
        let map = self.caches.lock().await;
        let now = Instant::now();
        map.iter().map(|(name, c)| {
            let secs = if c.expires_at > now { (c.expires_at - now).as_secs() } else { 0 };
            (name.clone(), secs)
        }).collect()
    }
}
