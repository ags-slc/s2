use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::error::S2Error;

/// Check that a file has 0600 permissions (owner read/write only).
/// Refuses to read files that are group or world readable.
pub fn check_permissions(path: &Path) -> Result<(), S2Error> {
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.mode() & 0o777;

    if mode & 0o077 != 0 {
        return Err(S2Error::UnsafePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }

    Ok(())
}

/// Set file permissions to 0600.
pub fn set_secure_permissions(path: &Path) -> Result<(), S2Error> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "test").unwrap();
        set_secure_permissions(&path).unwrap();
        check_permissions(&path).unwrap();
    }

    #[test]
    fn test_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "test").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_permissions(&path).is_err());
    }
}
