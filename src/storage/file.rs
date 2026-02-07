/// File system storage backend
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;

use super::StorageBackend;
use crate::error::{AcmeError, Result};

/// File-based storage
pub struct FileStorage {
    base_dir: PathBuf,
}

impl FileStorage {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    fn key_path(&self, key: &str) -> PathBuf {
        let sanitized = key.replace("/", "_");
        self.base_dir.join(format!("{}.bin", sanitized))
    }
}

#[async_trait]
impl StorageBackend for FileStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        fs::create_dir_all(&self.base_dir)
            .await
            .map_err(|e| AcmeError::storage(format!("Failed to create storage dir: {}", e)))?;

        let path = self.key_path(key);
        fs::write(path, value)
            .await
            .map_err(|e| AcmeError::storage(format!("Failed to write storage: {}", e)))?;
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.key_path(key);
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(path)
            .await
            .map_err(|e| AcmeError::storage(format!("Failed to read storage: {}", e)))?;
        Ok(Some(data))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_path(key);
        if path.exists() {
            fs::remove_file(path)
                .await
                .map_err(|e| AcmeError::storage(format!("Failed to delete storage: {}", e)))?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        if !self.base_dir.exists() {
            return Ok(keys);
        }

        let mut entries = fs::read_dir(&self.base_dir)
            .await
            .map_err(|e| AcmeError::storage(format!("Failed to list storage: {}", e)))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AcmeError::storage(format!("Failed to read storage entry: {}", e)))?
        {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.starts_with(prefix) {
                keys.push(file_name.to_string());
            }
        }

        Ok(keys)
    }
}
