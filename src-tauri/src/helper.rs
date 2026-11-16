//! Finding `netnima-helper` beside the app, and asking it its version.
//!
//! The installers put the helper beside the app's own program, and cargo
//! builds both into the same folder, so beside the app is where it is looked
//! for. For now the app only asks whether it is there and runs; later phases
//! start it to open low ports on Linux and to capture packets.

use std::path::PathBuf;
use std::process::Command;

use serde::Serialize;

/// What the app knows of its helper, for the welcome page and the About box.
#[derive(Clone, Debug, Default, Serialize)]
pub struct HelperInfo {
    /// Where the app looked for it.
    pub path: String,
    /// Its version, such as "0.1.0"; empty when it was not found or did not run.
    pub version: String,
    /// What is wrong with it, in words; empty when it is the helper of this very version.
    pub problem: String,
}

/// The helper's file, beside the app.
fn helper_path() -> std::io::Result<PathBuf> {
    let app = std::env::current_exe()?;
    Ok(app.with_file_name(format!("netnima-helper{}", std::env::consts::EXE_SUFFIX)))
}

/// The version in what `netnima-helper --version` says, such as "netnima-helper 0.1.0".
fn version_in(said: &str) -> Option<&str> {
    said.trim()
        .strip_prefix("netnima-helper ")
        .map(str::trim)
        .filter(|version| !version.is_empty())
}

/// Looks for the helper and runs it once.
fn look() -> HelperInfo {
    let path = match helper_path() {
        Ok(path) => path,
        Err(error) => {
            return HelperInfo {
                problem: format!("netNIMA could not tell where it is itself: {error}"),
                ..HelperInfo::default()
            };
        }
    };
    let shown = path.display().to_string();
    if !path.is_file() {
        return HelperInfo {
            path: shown,
            problem: "not found beside the app".into(),
            ..HelperInfo::default()
        };
    }
    let mut command = Command::new(&path);
    command.arg("--version");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window flashing up beside the app's own.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            return HelperInfo {
                path: shown,
                problem: format!("it did not start: {error}"),
                ..HelperInfo::default()
            };
        }
    };
    let said = String::from_utf8_lossy(&output.stdout);
    match version_in(&said) {
        Some(version) if output.status.success() => {
            let problem = if version == netnima_core::VERSION {
                String::new()
            } else {
                format!(
                    "it is version {version}, and the app {}: install netNIMA again",
                    netnima_core::VERSION
                )
            };
            HelperInfo {
                path: shown,
                version: version.to_string(),
                problem,
            }
        }
        _ => HelperInfo {
            path: shown,
            problem: format!("it did not say its version ({})", output.status),
            ..HelperInfo::default()
        },
    }
}

/// Whether the helper is beside the app, and which version it is.
#[tauri::command]
pub async fn helper_info() -> HelperInfo {
    tauri::async_runtime::spawn_blocking(look)
        .await
        .unwrap_or_else(|error| HelperInfo {
            problem: format!("looking for it failed: {error}"),
            ..HelperInfo::default()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_from_what_the_helper_says() {
        assert_eq!(version_in("netnima-helper 0.1.0\n"), Some("0.1.0"));
        assert_eq!(version_in("  netnima-helper 1.2.3  \r\n"), Some("1.2.3"));
        assert_eq!(version_in("netnima-helper "), None);
        assert_eq!(version_in("something else 0.1.0"), None);
        assert_eq!(version_in(""), None);
    }
}
