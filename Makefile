# SPDX-FileCopyrightText: 2025 Mohamed Hamdi <haamdi@outlook.com>
#
# SPDX-License-Identifier: MPL-2.0

# Hookshot - Secure webhook processing service written in Rust
# Makefile for development, building, and testing

# Configuration
BINARY_NAME := hookshot
TARGET_DIR := target

# Build configuration
RELEASE_TARGET := x86_64-unknown-linux-musl
DEBUG_PROFILE := debug
RELEASE_PROFILE := release

# Build artifacts
DEBUG_BINARY := $(TARGET_DIR)/$(DEBUG_PROFILE)/$(BINARY_NAME)
RELEASE_BINARY := $(TARGET_DIR)/$(RELEASE_TARGET)/$(RELEASE_PROFILE)/$(BINARY_NAME)

# Source files
RUST_SOURCES := $(shell find src -name "*.rs" 2>/dev/null) Cargo.toml Cargo.lock

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
RESET := \033[0m

# Default target
.DEFAULT_GOAL := help

# Only truly action-based targets should be PHONY
.PHONY: help all test clean fmt lint check dev release

help: ## Show this help message
	@echo "Hookshot Makefile"
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: $(DEBUG_BINARY) $(RELEASE_BINARY) ## Build both debug and release versions

# Build targets with proper dependencies
$(DEBUG_BINARY): $(RUST_SOURCES) ## Build debug version
	@echo -e "$(BLUE)Building $(BINARY_NAME) (debug)...$(RESET)"
	cargo build
	@echo -e "$(GREEN)Debug build complete$(RESET)"

$(RELEASE_BINARY): $(RUST_SOURCES) ## Build optimized release version with musl target
	@echo -e "$(BLUE)Building $(BINARY_NAME) (release) for $(RELEASE_TARGET)...$(RESET)"
	cargo build --release --target $(RELEASE_TARGET)
	@echo -e "$(GREEN)Release build complete$(RESET)"

# Convenience aliases
build: $(DEBUG_BINARY) ## Build debug version (alias)

release:
	cargo build --release --target $(RELEASE_TARGET)

# Testing with cargo nextest
test: ## Run all tests using cargo nextest
	@echo -e "$(BLUE)Running tests with cargo nextest...$(RESET)"
	cargo nextest run --no-fail-fast --all-features --failure-output=final --status-level fail
	@echo -e "$(GREEN)Tests completed$(RESET)"

# Code quality
fmt: ## Format code with rustfmt
	@echo -e "$(BLUE)Formatting code...$(RESET)"
	cargo fmt
	@echo -e "$(GREEN)Code formatting complete$(RESET)"

lint: ## Run clippy for code analysis
	@echo -e "$(BLUE)Running clippy...$(RESET)"
	cargo clippy  --all-targets --all-features -- -D warnings
	@echo -e "$(GREEN)Linting complete$(RESET)"

lint-fix: ## Run clippy for code analysis and fix all lint warnings
	@echo -e "$(BLUE)Running clippy...$(RESET)"
	cargo clippy --fix --allow-dirty -- -D warnings
	@echo -e "$(GREEN)Linting complete$(RESET)"

check: ## Fast compile check without building
	@echo -e "$(BLUE)Running compile check...$(RESET)"
	cargo check --all-targets --all-features
	@echo -e "$(GREEN)Compile check complete$(RESET)"

# Development workflow
dev: build test lint ## Development workflow: build + test + lint

dev-check: check test lint ## Fast development check: check + unit tests + lint

# Cleanup
clean: ## Clean build artifacts
	@echo -e "$(BLUE)Cleaning build artifacts...$(RESET)"
	cargo clean
	@echo -e "$(GREEN)Clean complete$(RESET)"

clean-all: clean ## Clean build artifacts and remove target directory
	@echo -e "$(BLUE)Removing target directory...$(RESET)"
	rm -rf $(TARGET_DIR)
	@echo -e "$(GREEN)Deep clean complete$(RESET)"

# Development debugging
debug-info: ## Show build and environment information
	@echo -e "$(BLUE)Build Information:$(RESET)"
	@echo "Binary name: $(BINARY_NAME)"
	@echo "Target directory: $(TARGET_DIR)"
	@echo "Release target: $(RELEASE_TARGET)"
	@echo ""
	@echo -e "$(BLUE)Environment:$(RESET)"
	@echo "Rust version: $$(rustc --version 2>/dev/null || echo 'Not found')"
	@echo "Cargo version: $$(cargo --version 2>/dev/null || echo 'Not found')"
