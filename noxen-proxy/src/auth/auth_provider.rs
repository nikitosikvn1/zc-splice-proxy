use std::io;
use std::error::Error;

use thiserror::Error;
use async_trait::async_trait;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials provided (username or password)")]
    InvalidCredentials,

    #[error("An underlying I/O error occurred during the authentication exchange")]
    Io(#[from] io::Error),

    #[error("Authentication service is temporarily unavailable")]
    Internal(#[source] Box<dyn Error + Send + Sync>),
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, username: &str, password: &str) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct StaticAuthProvider {
    username: String,
    password: String,
}

impl StaticAuthProvider {
    pub fn new<S: Into<String>>(username: S, password: S) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

#[async_trait]
impl AuthProvider for StaticAuthProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<(), AuthError> {
        if username == self.username && password == self.password {
            Ok(())
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }
}
