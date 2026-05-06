mod config;
mod token;
mod routes;

use axum::routing::get_service;
use tokio::net::TcpListener;
use tower_http::services::{ServeDir, ServeFile};
use reqwest::Client;
use routes::{AppState, router};
use token::TokenManager;

#[tokio::main]
async fn main() {
    let state = AppState {
        token_manager: TokenManager::new(),
        http: Client::new(),
    };

    let static_service = ServeDir::new("static")
    .fallback(ServeFile::new("static/index.html"));

    let app = router()
    .with_state(state)
    .fallback_service(get_service(static_service));
    
    let listener = TcpListener::bind("127.0.0.1:8000").await.unwrap();
    println!("ferrous -> http://localhost:8000");
    axum::serve(listener, app).await.unwrap();
}