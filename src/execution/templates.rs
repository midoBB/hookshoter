use handlebars::Handlebars;
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::config::types::ServiceConfig;
use crate::types::{Result, TemplateExpansionError};

/// Context for template variable expansion
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Built-in template variables
    pub built_in: HashMap<String, String>,
    /// Custom template variables from service configuration
    pub custom: HashMap<String, String>,
    /// Runtime variables from deployment metadata
    pub runtime: HashMap<String, String>,
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new() -> Self {
        Self {
            built_in: HashMap::new(),
            custom: HashMap::new(),
            runtime: HashMap::new(),
        }
    }

    /// Builder pattern: set built-in variables
    pub fn with_built_in_variables(
        mut self,
        image: String,
        service: String,
        deploy_id: String,
        working_dir: String,
    ) -> Self {
        let timestamp = chrono::Utc::now().timestamp().to_string();

        self.built_in.insert("IMAGE".to_string(), image);
        self.built_in.insert("SERVICE".to_string(), service);
        self.built_in.insert("DEPLOY_ID".to_string(), deploy_id);
        self.built_in.insert("WORKING_DIR".to_string(), working_dir);
        self.built_in.insert("TIMESTAMP".to_string(), timestamp);

        self
    }

    /// Builder pattern: set previous image for rollback scenarios
    pub fn with_previous_image(mut self, previous_image: Option<String>) -> Self {
        if let Some(image) = previous_image {
            self.built_in.insert("PREVIOUS_IMAGE".to_string(), image);
        }
        self
    }

    /// Builder pattern: add custom variables from service configuration
    pub fn with_custom_variables(mut self, service_config: &ServiceConfig) -> Self {
        for (key, value) in &service_config.templates {
            self.custom.insert(key.clone(), value.clone());
        }
        self
    }

    /// Builder pattern: add runtime variables from deployment metadata
    pub fn with_runtime_variables(mut self, metadata: HashMap<String, String>) -> Self {
        self.runtime = metadata;
        self
    }

    /// Get all variables combined (runtime > custom > built-in priority)
    fn get_all_variables(&self) -> HashMap<String, String> {
        let mut variables = self.built_in.clone();
        variables.extend(self.custom.clone());
        variables.extend(self.runtime.clone());
        variables
    }

    /// Check if a variable exists in the context
    pub fn has_variable(&self, name: &str) -> bool {
        self.built_in.contains_key(name)
            || self.custom.contains_key(name)
            || self.runtime.contains_key(name)
    }

    /// Validate that a template variable value is safe for shell execution
    fn is_safe_template_value(value: &str) -> bool {
        // Check for dangerous characters and patterns that could enable shell injection
        let dangerous_chars = ['$', '`', ';', '|', '&', '>', '<', '\\', '"', '\''];
        let dangerous_patterns = [
            "$(", "``", "||", "&&", ">>", "<<", " && ", " || ", "; ", "| ",
        ];

        // Check for dangerous characters
        for ch in value.chars() {
            if dangerous_chars.contains(&ch) {
                return false;
            }
        }

        // Check for dangerous patterns
        for pattern in &dangerous_patterns {
            if value.contains(pattern) {
                return false;
            }
        }

        // Additional check for control characters (except newline and tab which might be legitimate)
        if value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return false;
        }

        // Reject empty or whitespace-only values
        if value.trim().is_empty() {
            return false;
        }

        true
    }

    /// Expand templates in a command argument (with support for nested templates)
    pub fn expand_command_arg(&self, template: &str) -> Result<String> {
        debug!(template = %template, "Expanding template");

        let mut handlebars = Handlebars::new();
        handlebars.set_strict_mode(true); // Fail on undefined variables

        // First, expand any custom variables that might contain templates themselves
        let mut expanded_variables = HashMap::new();
        for (key, value) in &self.built_in {
            expanded_variables.insert(key.clone(), value.clone());
        }
        for (key, value) in &self.runtime {
            expanded_variables.insert(key.clone(), value.clone());
        }

        // Expand custom variables that might reference other variables
        for (key, value) in &self.custom {
            if value.contains("{{") {
                // This custom variable contains templates, expand it
                let expanded_custom = handlebars
                    .render_template(value, &expanded_variables)
                    .map_err(|e| {
                        crate::types::Error::TemplateExpansion(
                            TemplateExpansionError::RenderError { source: e },
                        )
                    })?;
                expanded_variables.insert(key.clone(), expanded_custom);
            } else {
                expanded_variables.insert(key.clone(), value.clone());
            }
        }

        // Now expand the main template with all resolved variables
        let expanded = handlebars
            .render_template(template, &expanded_variables)
            .map_err(|e| {
                crate::types::Error::TemplateExpansion(TemplateExpansionError::RenderError {
                    source: e,
                })
            })?;

        // Validate that no unexpanded templates remain
        if expanded.contains("{{") || expanded.contains("}}") {
            return Err(crate::types::Error::TemplateExpansion(
                TemplateExpansionError::UnexpandedTemplate { template: expanded },
            ));
        }

        // Validate the final expanded value is safe for shell execution
        if !Self::is_safe_template_value(&expanded) {
            warn!(
                template = %template,
                expanded = %expanded,
                "Expanded template contains unsafe value"
            );
            return Err(crate::types::Error::TemplateExpansion(
                TemplateExpansionError::UnsafeValue {
                    variable: template.to_string(),
                    value: expanded,
                },
            ));
        }

        debug!(
            original = %template,
            expanded = %expanded,
            "Template expansion completed"
        );

        Ok(expanded)
    }

    /// Expand templates in all command arguments
    pub fn expand_command(&self, command: &[String]) -> Result<Vec<String>> {
        let mut expanded_command = Vec::with_capacity(command.len());

        for arg in command {
            let expanded_arg = self.expand_command_arg(arg)?;
            expanded_command.push(expanded_arg);
        }

        Ok(expanded_command)
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{ServiceConfig, ServiceDeploy, ServiceSecurity};

    fn create_test_service_config() -> ServiceConfig {
        let mut templates = HashMap::new();
        templates.insert(
            "CONTAINER_NAME".to_string(),
            "{{SERVICE}}-{{TIMESTAMP}}".to_string(),
        );
        templates.insert(
            "BACKUP_TAG".to_string(),
            "rollback-{{DEPLOY_ID}}".to_string(),
        );

        ServiceConfig {
            name: "test-service".to_string(),
            description: Some("Test service".to_string()),
            enabled: true,
            working_dir: Some("/srv/test".to_string()),
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: ".*".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: Default::default(),
            rollback: Default::default(),
            hooks: Default::default(),
            templates,
            github: None,
        }
    }

    #[test]
    fn test_execution_context_creation() {
        let context = ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v1.0.0".to_string(),
            "web-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        );

        assert_eq!(
            context.built_in.get("IMAGE"),
            Some(&"registry:5000/app:v1.0.0".to_string())
        );
        assert_eq!(
            context.built_in.get("SERVICE"),
            Some(&"web-service".to_string())
        );
        assert_eq!(
            context.built_in.get("DEPLOY_ID"),
            Some(&"deploy-001".to_string())
        );
        assert_eq!(
            context.built_in.get("WORKING_DIR"),
            Some(&"/srv/app".to_string())
        );
        assert!(context.built_in.contains_key("TIMESTAMP"));
    }

    #[test]
    fn test_template_expansion_basic() {
        let context = ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v1.0.0".to_string(),
            "web-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        );

        let expanded = context.expand_command_arg("podman pull {{IMAGE}}").unwrap();
        assert!(expanded.contains("registry:5000/app:v1.0.0"));
        assert!(expanded.starts_with("podman pull "));
    }

    #[test]
    fn test_template_expansion_with_custom_variables() {
        let service_config = create_test_service_config();
        let context = ExecutionContext::new()
            .with_built_in_variables(
                "registry:5000/app:v1.0.0".to_string(),
                "web-service".to_string(),
                "deploy-001".to_string(),
                "/srv/app".to_string(),
            )
            .with_custom_variables(&service_config);

        let expanded = context
            .expand_command_arg("docker run --name {{CONTAINER_NAME}} {{IMAGE}}")
            .unwrap();
        assert!(expanded.contains("web-service"));
        assert!(expanded.contains("registry:5000/app:v1.0.0"));
    }

    #[test]
    fn test_template_expansion_with_previous_image() {
        let context = ExecutionContext::new()
            .with_built_in_variables(
                "registry:5000/app:v2.0.0".to_string(),
                "web-service".to_string(),
                "deploy-002".to_string(),
                "/srv/app".to_string(),
            )
            .with_previous_image(Some("registry:5000/app:v1.0.0".to_string()));

        let expanded = context
            .expand_command_arg("podman pull {{PREVIOUS_IMAGE}}")
            .unwrap();
        assert!(expanded.contains("registry:5000/app:v1.0.0"));
    }

    #[test]
    fn test_undefined_variable_error() {
        let context = ExecutionContext::new();

        let result = context.expand_command_arg("echo {{UNDEFINED_VAR}}");
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::types::Error::TemplateExpansion(TemplateExpansionError::RenderError {
                ..
            }) => {} // Expected
            e => panic!("Expected RenderError, got: {:?}", e),
        }
    }

    #[test]
    fn test_unsafe_template_value() {
        let mut context = ExecutionContext::new();
        context
            .built_in
            .insert("UNSAFE_VAR".to_string(), "value; rm -rf /".to_string());

        let result = context.expand_command_arg("echo {{UNSAFE_VAR}}");
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::types::Error::TemplateExpansion(TemplateExpansionError::UnsafeValue {
                variable,
                ..
            }) => {
                assert!(variable.contains("UNSAFE_VAR"));
            }
            e => panic!("Expected UnsafeValue error, got: {:?}", e),
        }
    }

    #[test]
    fn test_expand_full_command() {
        let context = ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v1.0.0".to_string(),
            "web-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        );

        let command = vec![
            "podman".to_string(),
            "run".to_string(),
            "--name".to_string(),
            "{{SERVICE}}-container".to_string(),
            "{{IMAGE}}".to_string(),
        ];

        let expanded = context.expand_command(&command).unwrap();
        assert_eq!(expanded.len(), 5);
        assert_eq!(expanded[0], "podman");
        assert_eq!(expanded[1], "run");
        assert_eq!(expanded[2], "--name");
        assert!(expanded[3].contains("web-service"));
        assert!(expanded[4].contains("registry:5000/app:v1.0.0"));
    }

    #[test]
    fn test_safe_template_value_validation() {
        assert!(ExecutionContext::is_safe_template_value(
            "registry:5000/app:v1.0.0"
        ));
        assert!(ExecutionContext::is_safe_template_value("web-service"));
        assert!(ExecutionContext::is_safe_template_value("deploy-001"));
        assert!(ExecutionContext::is_safe_template_value("/srv/app"));

        // Unsafe values
        assert!(!ExecutionContext::is_safe_template_value("value; rm -rf /"));
        assert!(!ExecutionContext::is_safe_template_value(
            "value && dangerous"
        ));
        assert!(!ExecutionContext::is_safe_template_value("value $(whoami)"));
        assert!(!ExecutionContext::is_safe_template_value("value `command`"));
        assert!(!ExecutionContext::is_safe_template_value(
            "value | grep secret"
        ));
    }

    #[test]
    fn test_runtime_variables_priority() {
        let service_config = create_test_service_config();
        let mut runtime_vars = HashMap::new();
        runtime_vars.insert("SERVICE".to_string(), "override-service".to_string());

        let context = ExecutionContext::new()
            .with_built_in_variables(
                "registry:5000/app:v1.0.0".to_string(),
                "web-service".to_string(),
                "deploy-001".to_string(),
                "/srv/app".to_string(),
            )
            .with_custom_variables(&service_config)
            .with_runtime_variables(runtime_vars);

        let expanded = context.expand_command_arg("echo {{SERVICE}}").unwrap();
        assert!(expanded.contains("override-service"));
    }
}
