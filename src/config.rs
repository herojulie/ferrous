use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub client_secret: String,
    pub audience: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Named Auth0 credential profiles. Key is the profile name
    #[serde(default)]    
    pub profiles: HashMap<String, Auth0Config>,

    /// Saved API requests
    #[serde(default)]
    pub saved_requests: Vec<serde_json::Value>,
}

fn config_path() -> PathBuf {
    PathBuf::from("config.json")
}

pub fn load_config() -> AppConfig {
    let path = config_path();
    if !path.exists() {
        return AppConfig::default();
    }
    let content = fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

pub fn save_config(cfg: &AppConfig) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(cfg)?;
    fs::write(config_path(), json)?;
    Ok(())
}
