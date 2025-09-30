pub mod executor;
pub mod templates;

// Re-export the main types and functions for easier usage
// Note: These will be used by other modules when the HTTP API is implemented
#[allow(unused_imports)]
pub use executor::{
    execute_with_retry, execute_with_retry_and_context, CommandExecutor, ExecutionStep,
};
#[allow(unused_imports)]
pub use templates::ExecutionContext;
