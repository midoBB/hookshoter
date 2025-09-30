use thiserror::Error;

/// Main error type for the application
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Validation failed: {field}: {message}")]
    Validation { field: String, message: String },

    #[error("Application error: {0}")]
    Application(String),
}

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Config file not found: {path}")]
    FileNotFound { path: String },

    #[error("Config file parse error: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid configuration: {message}")]
    Invalid { message: String },

    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

/// Type alias for Results
pub type Result<T> = std::result::Result<T, Error>;