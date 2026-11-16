//! Reading and writing netNIMA's TOML files, such as `settings.toml`.

use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Reads a value from `path`.
///
/// A missing file gives the default. So does a broken one, so a bad edit never
/// stops the app from starting; the broken file is first copied to
/// `<name>.bad.toml` beside it, so the edit is not lost when the app saves.
pub fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    let Ok(text) = fs::read_to_string(path) else {
        return T::default();
    };
    match toml::from_str(&text) {
        Ok(value) => value,
        Err(_) => {
            let _ = fs::copy(path, path.with_extension("bad.toml"));
            T::default()
        }
    }
}

/// Writes a value to `path` with `header` above it, making the folder if needed.
///
/// The text goes to a temporary file first, which then replaces the old one,
/// so a crash or power cut never leaves a half written file behind.
pub fn save<T: Serialize>(value: &T, path: &Path, header: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = toml::to_string_pretty(value).map_err(io::Error::other)?;
    let temp = path.with_extension("toml.tmp");
    fs::write(&temp, format!("{header}{body}"))?;
    fs::rename(&temp, path)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use super::*;

    /// An empty folder for one test, removed again when the test ends.
    pub(crate) struct TempDir(PathBuf);

    impl TempDir {
        pub(crate) fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("netnima-test-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        pub(crate) fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_save_leaves_no_temporary_file_behind() {
        let dir = TempDir::new("tomlfile-temp");
        let path = dir.file("deep/folder/value.toml");
        let value: std::collections::BTreeMap<_, _> = [("a", 1)].into();
        save(&value, &path, "# test\n").unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("toml.tmp").exists());
        assert!(fs::read_to_string(&path).unwrap().starts_with("# test\n"));
    }
}
