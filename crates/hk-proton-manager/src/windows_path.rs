//! Windows 私有状态目录边界。
//!
//! 这里的检查不会解析或跟随 symlink、junction 等重解析点。调用方在每次敏感
//! 写入和删除前重新验证目录，避免提升后的进程把用户可写路径当成可信目录。

use std::{
    ffi::OsStr,
    fs::{self, File, Metadata, OpenOptions},
    io,
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use crate::{ManagerError, Result};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[derive(Clone, Debug)]
pub struct WindowsPrivateDirectory {
    canonical_anchor: PathBuf,
    canonical_path: PathBuf,
}

impl WindowsPrivateDirectory {
    /// 创建（或打开）`target`，并把它限制在 `anchor` 内。
    ///
    /// `target` 必须由 `anchor` 直接拼出；两者之间的每一级目录都拒绝重解析点。
    pub fn create(anchor: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<Self> {
        let anchor = anchor.as_ref();
        let target = target.as_ref();
        if !anchor.is_absolute() || !target.is_absolute() || !target.starts_with(anchor) {
            return Err(ManagerError::UnsafePrivatePath);
        }
        let relative = target
            .strip_prefix(anchor)
            .map_err(|_| ManagerError::UnsafePrivatePath)?;
        validate_relative_directory(relative)?;

        create_or_verify_directory(anchor)?;
        let canonical_anchor = anchor.canonicalize()?;
        verify_directory(anchor)?;

        let mut current = anchor.to_path_buf();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(ManagerError::UnsafePrivatePath);
            };
            current.push(name);
            create_or_verify_directory(&current)?;
        }

        let canonical_path = target.canonicalize()?;
        if !canonical_path.starts_with(&canonical_anchor) {
            return Err(ManagerError::UnsafePrivatePath);
        }
        let directory = Self {
            canonical_anchor,
            canonical_path,
        };
        directory.revalidate()?;
        Ok(directory)
    }

    pub fn path(&self) -> &Path {
        &self.canonical_path
    }

    pub fn create_child(&self, name: impl AsRef<OsStr>) -> Result<Self> {
        self.revalidate()?;
        let name = checked_file_name(name.as_ref())?;
        Self::create(&self.canonical_anchor, self.canonical_path.join(name))
    }

    /// 写入、删除或交给子进程前重新验证整个可信链。
    pub fn revalidate(&self) -> Result<()> {
        verify_directory(&self.canonical_anchor)?;
        if !self.canonical_path.starts_with(&self.canonical_anchor) {
            return Err(ManagerError::UnsafePrivatePath);
        }

        let relative = self
            .canonical_path
            .strip_prefix(&self.canonical_anchor)
            .map_err(|_| ManagerError::UnsafePrivatePath)?;
        validate_relative_directory(relative)?;
        let mut current = self.canonical_anchor.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(ManagerError::UnsafePrivatePath);
            };
            current.push(name);
            verify_directory(&current)?;
        }

        if self.canonical_anchor.canonicalize()? != self.canonical_anchor
            || self.canonical_path.canonicalize()? != self.canonical_path
        {
            return Err(ManagerError::UnsafePrivatePath);
        }
        Ok(())
    }

    pub fn existing_regular_file(&self, name: impl AsRef<OsStr>) -> Result<Option<PathBuf>> {
        self.revalidate()?;
        let path = self.canonical_path.join(checked_file_name(name.as_ref())?);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                verify_regular_file(&metadata)?;
                Ok(Some(path))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn create_new_file(&self, name: impl AsRef<OsStr>) -> Result<(PathBuf, File)> {
        self.revalidate()?;
        let path = self.canonical_path.join(checked_file_name(name.as_ref())?);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        verify_regular_file(&file.metadata()?)?;
        self.revalidate()?;
        Ok((path, file))
    }

    pub fn remove_regular_file(&self, name: impl AsRef<OsStr>) -> Result<()> {
        self.revalidate()?;
        let path = self.canonical_path.join(checked_file_name(name.as_ref())?);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                verify_regular_file(&metadata)?;
                fs::remove_file(path)?;
                self.revalidate()
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn create_or_verify_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => verify_directory_metadata(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            verify_directory(path)
        }
        Err(error) => Err(error.into()),
    }
}

fn verify_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    verify_directory_metadata(&metadata)
}

fn verify_directory_metadata(metadata: &Metadata) -> Result<()> {
    if !metadata.is_dir() || is_link_or_reparse(metadata) {
        return Err(ManagerError::UnsafePrivatePath);
    }
    Ok(())
}

fn verify_regular_file(metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() || is_link_or_reparse(metadata) {
        return Err(ManagerError::UnsafePrivatePath);
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink() || is_reparse_attributes(metadata.file_attributes())
}

fn is_reparse_attributes(attributes: u32) -> bool {
    attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn validate_relative_directory(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ManagerError::UnsafePrivatePath);
    }
    Ok(())
}

fn checked_file_name(name: &OsStr) -> Result<&OsStr> {
    let path = Path::new(name);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Ok(name),
        _ => Err(ManagerError::UnsafePrivatePath),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn rejects_reparse_attribute_and_path_traversal_without_touching_the_system() {
        assert!(is_reparse_attributes(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(!is_reparse_attributes(0));
        assert!(checked_file_name(OsStr::new("profile.yaml")).is_ok());
        assert!(checked_file_name(OsStr::new("../profile.yaml")).is_err());
        assert!(validate_relative_directory(Path::new("runtime/cache")).is_ok());
        assert!(validate_relative_directory(Path::new("runtime/../outside")).is_err());
    }

    #[test]
    fn creates_and_revalidates_only_descendants_of_the_anchor() {
        let temporary = TempDir::new().unwrap();
        let anchor = temporary.path().join("app-data");
        let state = anchor.join("state-vault");
        let state_scope = WindowsPrivateDirectory::create(&anchor, &state).unwrap();
        let runtime_scope = state_scope.create_child("runtime").unwrap();

        assert!(runtime_scope.path().starts_with(state_scope.path()));
        runtime_scope.revalidate().unwrap();
        assert!(
            WindowsPrivateDirectory::create(&anchor, temporary.path().join("outside")).is_err()
        );
    }
}
