use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};
use tracing::{debug, info, warn};

use crate::types::{BackupError, Result};

/// Information about a file in the backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub original_path: String,
    pub checksum: String,
    pub size: u64,
}

/// Manifest containing backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: String,
    pub created_at: i64,
    pub hookshot_version: String,
    pub files: HashMap<String, FileInfo>,
}

/// Information about a backup archive
#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub version: String,
    pub created_at: i64,
    pub hookshot_version: String,
    pub file_count: usize,
    pub total_size: u64,
}

impl BackupManifest {
    /// Create a new backup manifest
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            hookshot_version: env!("CARGO_PKG_VERSION").to_string(),
            files: HashMap::new(),
        }
    }

    /// Add a file to the manifest
    pub fn add_file(&mut self, name: String, path: &Path, original_path: &Path) -> Result<()> {
        let metadata = fs::metadata(path)?;
        let checksum = calculate_checksum(path)?;

        self.files.insert(
            name.clone(),
            FileInfo {
                path: name,
                original_path: original_path.display().to_string(),
                checksum,
                size: metadata.len(),
            },
        );

        Ok(())
    }

    /// Validate the manifest
    pub fn validate(&self) -> Result<()> {
        if self.version.is_empty() {
            return Err(
                BackupError::ManifestParseFailed("manifest version is empty".to_string()).into(),
            );
        }

        if self.hookshot_version.is_empty() {
            return Err(
                BackupError::ManifestParseFailed("hookshot version is empty".to_string()).into(),
            );
        }

        if self.files.is_empty() {
            return Err(
                BackupError::ManifestParseFailed("no files in manifest".to_string()).into(),
            );
        }

        Ok(())
    }

    /// Check version compatibility
    pub fn check_version_compatibility(&self) -> Result<()> {
        let current_version = env!("CARGO_PKG_VERSION");

        // For now, only check major version compatibility
        let backup_major = self
            .hookshot_version
            .split('.')
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        let current_major = current_version
            .split('.')
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        if backup_major != current_major {
            return Err(BackupError::VersionIncompatible {
                backup_version: self.hookshot_version.clone(),
                current_version: current_version.to_string(),
            }
            .into());
        }

        Ok(())
    }

    /// Get backup info from manifest
    pub fn to_backup_info(&self) -> BackupInfo {
        let total_size = self.files.values().map(|f| f.size).sum();

        BackupInfo {
            version: self.version.clone(),
            created_at: self.created_at,
            hookshot_version: self.hookshot_version.clone(),
            file_count: self.files.len(),
            total_size,
        }
    }
}

/// Calculate SHA256 checksum of a file
fn calculate_checksum(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Verify a file's checksum matches expected value
fn verify_checksum(path: &Path, expected: &str) -> Result<()> {
    let actual = calculate_checksum(path)?;

    if actual != expected {
        return Err(BackupError::ChecksumMismatch {
            file: path.display().to_string(),
            expected: expected.to_string(),
            actual,
        }
        .into());
    }

    Ok(())
}

/// Create a backup archive
pub fn create_backup(
    output_path: &Path,
    config_path: &Path,
    services_path: &Path,
    data_dir: &Path,
) -> Result<()> {
    info!(
        output = %output_path.display(),
        "Creating backup archive"
    );

    // Create temporary directory for staging
    let temp_dir = tempfile::tempdir()?;
    let staging_dir = temp_dir.path();

    // Generate timestamp for the archive directory name
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let archive_dir_name = format!("hookshot-state-{}", timestamp);
    let archive_staging = staging_dir.join(&archive_dir_name);
    fs::create_dir_all(&archive_staging)?;

    // Create manifest
    let mut manifest = BackupManifest::new();

    // Copy database file
    let db_path = data_dir.join("state.redb");
    if db_path.exists() {
        let dest = archive_staging.join("state.redb");
        fs::copy(&db_path, &dest)?;
        manifest.add_file("state.redb".to_string(), &dest, &db_path)?;
        info!("Added database to backup");
    } else {
        warn!("Database file not found, skipping");
    }

    // Copy system config
    if config_path.exists() {
        let dest = archive_staging.join("config.toml");
        fs::copy(config_path, &dest)?;
        manifest.add_file("config.toml".to_string(), &dest, config_path)?;
        info!("Added system config to backup");
    } else {
        warn!("System config not found, skipping");
    }

    // Copy services config
    if services_path.exists() {
        let dest = archive_staging.join("services.toml");
        fs::copy(services_path, &dest)?;
        manifest.add_file("services.toml".to_string(), &dest, services_path)?;
        info!("Added services config to backup");
    } else {
        warn!("Services config not found, skipping");
    }

    // Check for secrets file (try multiple common locations)
    let mut secrets_locations = vec![
        PathBuf::from("/etc/hookshot/secrets"),
        data_dir.join("secrets"),
    ];

    if let Some(parent) = config_path.parent() {
        secrets_locations.push(parent.join("secrets"));
    }

    for secrets_path in secrets_locations {
        if secrets_path.exists() {
            let dest = archive_staging.join("secrets");
            fs::copy(&secrets_path, &dest)?;
            manifest.add_file("secrets".to_string(), &dest, &secrets_path)?;
            info!("Added secrets file to backup");
            break;
        }
    }

    // Write manifest
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| BackupError::ManifestParseFailed(e.to_string()))?;
    let manifest_path = archive_staging.join("manifest.json");
    fs::write(&manifest_path, manifest_json)?;

    // Create tar.gz archive
    let tar_gz = File::create(output_path)?;
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = Builder::new(enc);

    // Add the archive directory recursively
    tar.append_dir_all(&archive_dir_name, &archive_staging)?;
    tar.finish()?;

    let backup_info = manifest.to_backup_info();
    info!(
        output = %output_path.display(),
        files = backup_info.file_count,
        size_bytes = backup_info.total_size,
        "Backup created successfully"
    );

    Ok(())
}

/// Validate a backup archive
pub fn validate_backup(backup_path: &Path) -> Result<BackupInfo> {
    info!(
        backup = %backup_path.display(),
        "Validating backup archive"
    );

    // Extract to temporary directory
    let temp_dir = tempfile::tempdir()?;
    let extract_dir = temp_dir.path();

    // Extract tar.gz
    let tar_gz = File::open(backup_path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(extract_dir)?;

    // Find the archive directory (should be only one)
    let entries: Vec<_> = fs::read_dir(extract_dir)?.filter_map(|e| e.ok()).collect();

    if entries.is_empty() {
        return Err(BackupError::InvalidArchive("archive is empty".to_string()).into());
    }

    if entries.len() > 1 {
        return Err(BackupError::InvalidArchive(
            "archive contains multiple top-level directories".to_string(),
        )
        .into());
    }

    let archive_dir = entries[0].path();
    if !archive_dir.is_dir() {
        return Err(
            BackupError::InvalidArchive("archive root is not a directory".to_string()).into(),
        );
    }

    // Read and parse manifest
    let manifest_path = archive_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(BackupError::MissingFile("manifest.json".to_string()).into());
    }

    let manifest_content = fs::read_to_string(&manifest_path)?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_content)
        .map_err(|e| BackupError::ManifestParseFailed(e.to_string()))?;

    // Validate manifest structure
    manifest.validate()?;

    // Verify checksums for all files
    for (name, file_info) in &manifest.files {
        let file_path = archive_dir.join(name);
        if !file_path.exists() {
            return Err(BackupError::MissingFile(name.clone()).into());
        }

        verify_checksum(&file_path, &file_info.checksum)?;
        debug!(file = %name, "Checksum verified");
    }

    // Check version compatibility
    manifest.check_version_compatibility()?;

    info!("Backup validation successful");
    Ok(manifest.to_backup_info())
}

/// Restore from a backup archive
pub fn restore_backup(
    backup_path: &Path,
    dry_run: bool,
    force: bool,
    has_active_deployments_fn: Option<impl Fn() -> Result<bool>>,
) -> Result<()> {
    info!(
        backup = %backup_path.display(),
        dry_run = dry_run,
        "Starting backup restoration"
    );

    // First validate the backup
    let backup_info = validate_backup(backup_path)?;

    info!(
        version = %backup_info.hookshot_version,
        created_at = backup_info.created_at,
        files = backup_info.file_count,
        "Backup validated successfully"
    );

    if dry_run {
        info!("DRY RUN MODE - No changes will be made");
        info!("The following files would be restored:");
    }

    // Extract to temporary directory
    let temp_dir = tempfile::tempdir()?;
    let extract_dir = temp_dir.path();

    let tar_gz = File::open(backup_path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(extract_dir)?;

    // Find archive directory
    let entries: Vec<_> = fs::read_dir(extract_dir)?.filter_map(|e| e.ok()).collect();
    let archive_dir = entries[0].path();

    // Read manifest
    let manifest_path = archive_dir.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path)?;
    let manifest: BackupManifest = serde_json::from_str(&manifest_content)
        .map_err(|e| BackupError::ManifestParseFailed(e.to_string()))?;

    // Check for active deployments
    if !force {
        if let Some(check_fn) = has_active_deployments_fn {
            if check_fn()? {
                return Err(BackupError::ActiveDeployments.into());
            }
        }
    }

    // Plan restoration using original paths from manifest
    let mut restore_plan = Vec::new();

    for (file_name, file_info) in &manifest.files {
        let dest_path = PathBuf::from(&file_info.original_path);
        restore_plan.push((file_name.as_str(), dest_path));
    }

    // Display or execute restoration plan
    for (file_name, dest_path) in &restore_plan {
        if dry_run {
            info!("  {} -> {}", file_name, dest_path.display());
        } else {
            // Create backup of existing file
            if dest_path.exists() {
                let backup_path = dest_path.with_extension("bak");
                fs::copy(dest_path, &backup_path)?;
                debug!(
                    original = %dest_path.display(),
                    backup = %backup_path.display(),
                    "Created backup of existing file"
                );
            }

            // Ensure parent directory exists
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Copy file from archive to destination
            let source_path = archive_dir.join(file_name);
            fs::copy(&source_path, dest_path)?;

            // Verify checksum after copy
            if let Some(file_info) = manifest.files.get(*file_name) {
                verify_checksum(dest_path, &file_info.checksum)?;
            }

            info!(
                file = %file_name,
                dest = %dest_path.display(),
                "Restored file successfully"
            );
        }
    }

    if dry_run {
        info!("DRY RUN COMPLETE - No changes were made");
    } else {
        info!(
            files_restored = restore_plan.len(),
            "Backup restoration completed successfully"
        );
        info!("Previous files backed up with .bak extension");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_calculate_checksum() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        let checksum = calculate_checksum(&file_path).unwrap();
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 64); // SHA256 hex string length

        // Same content should produce same checksum
        let checksum2 = calculate_checksum(&file_path).unwrap();
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_verify_checksum_success() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        let checksum = calculate_checksum(&file_path).unwrap();
        assert!(verify_checksum(&file_path, &checksum).is_ok());
    }

    #[test]
    fn test_verify_checksum_failure() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        let result = verify_checksum(&file_path, "wrong_checksum");
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_creation() {
        let manifest = BackupManifest::new();
        assert_eq!(manifest.version, "1.0");
        assert!(!manifest.hookshot_version.is_empty());
        assert!(manifest.files.is_empty());
    }

    #[test]
    fn test_manifest_add_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        let mut manifest = BackupManifest::new();
        manifest
            .add_file("test.txt".to_string(), &file_path, &file_path)
            .unwrap();

        assert_eq!(manifest.files.len(), 1);
        assert!(manifest.files.contains_key("test.txt"));
        assert_eq!(
            manifest.files.get("test.txt").unwrap().original_path,
            file_path.display().to_string()
        );
    }

    #[test]
    fn test_manifest_validation_empty() {
        let manifest = BackupManifest::new();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_manifest_validation_success() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test content").unwrap();
        drop(file);

        let mut manifest = BackupManifest::new();
        manifest
            .add_file("test.txt".to_string(), &file_path, &file_path)
            .unwrap();

        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_version_compatibility() {
        let manifest = BackupManifest {
            version: "1.0".to_string(),
            created_at: chrono::Utc::now().timestamp(),
            hookshot_version: env!("CARGO_PKG_VERSION").to_string(),
            files: HashMap::new(),
        };

        assert!(manifest.check_version_compatibility().is_ok());
    }

    #[test]
    fn test_create_and_validate_backup() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let config_dir = temp_dir.path().join("config");

        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();

        // Create mock files
        let db_path = data_dir.join("state.redb");
        fs::write(&db_path, b"mock database").unwrap();

        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, b"[server]\nlisten = \"127.0.0.1:8080\"").unwrap();

        let services_path = config_dir.join("services.toml");
        fs::write(&services_path, b"[[service]]\nname = \"test\"").unwrap();

        // Create backup
        let backup_path = temp_dir.path().join("backup.tar.gz");
        create_backup(&backup_path, &config_path, &services_path, &data_dir).unwrap();

        assert!(backup_path.exists());

        // Validate backup
        let backup_info = validate_backup(&backup_path).unwrap();
        assert_eq!(backup_info.hookshot_version, env!("CARGO_PKG_VERSION"));
        assert!(backup_info.file_count >= 3); // At least db, config, services
    }

    #[test]
    fn test_restore_backup_dry_run() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let config_dir = temp_dir.path().join("config");
        let restore_dir = temp_dir.path().join("restore");

        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&restore_dir).unwrap();

        // Create mock files
        let db_path = data_dir.join("state.redb");
        fs::write(&db_path, b"mock database").unwrap();

        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, b"[server]\nlisten = \"127.0.0.1:8080\"").unwrap();

        let services_path = config_dir.join("services.toml");
        fs::write(&services_path, b"[[service]]\nname = \"test\"").unwrap();

        // Create backup
        let backup_path = temp_dir.path().join("backup.tar.gz");
        create_backup(&backup_path, &config_path, &services_path, &data_dir).unwrap();

        // Dry run restore
        restore_backup(
            &backup_path,
            true,
            false,
            Some(|| Ok(false)),
        )
        .unwrap();

        // Files should not exist in restore_dir after dry run
        // (they would be restored to original paths)
        let restore_config = restore_dir.join("config.toml");
        let restore_services = restore_dir.join("services.toml");
        assert!(!restore_config.exists());
        assert!(!restore_services.exists());
    }

    #[test]
    fn test_restore_backup_with_active_deployments() {
        let temp_dir = tempdir().unwrap();
        let backup_path = temp_dir.path().join("backup.tar.gz");

        // Create a minimal valid backup
        let data_dir = temp_dir.path().join("data");
        let config_dir = temp_dir.path().join("config");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&config_dir).unwrap();

        let db_path = data_dir.join("state.redb");
        fs::write(&db_path, b"mock database").unwrap();

        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, b"[server]\nlisten = \"127.0.0.1:8080\"").unwrap();

        let services_path = config_dir.join("services.toml");
        fs::write(&services_path, b"[[service]]\nname = \"test\"").unwrap();

        create_backup(&backup_path, &config_path, &services_path, &data_dir).unwrap();

        // Try to restore with active deployments
        let result = restore_backup(
            &backup_path,
            false,
            false,
            Some(|| Ok(true)), // Simulate active deployments
        );

        assert!(result.is_err());
        match result {
            Err(crate::types::Error::Backup(BackupError::ActiveDeployments)) => {}
            _ => panic!("Expected ActiveDeployments error"),
        }
    }
}
