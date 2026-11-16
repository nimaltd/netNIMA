//! netnima-helper: the only part of netNIMA that will hold rights.
//!
//! The app never runs as administrator or root. What needs rights goes
//! through this small program instead, as Wireshark's `dumpcap` does for
//! Wireshark: on Linux it will open server ports below 1024 and hand them to
//! the app, and on every OS it will capture packets. The installers put it
//! beside the app. For now it only says its version, so the app and the
//! release workflow can tell it is there and that it runs.

use std::process::ExitCode;

/// The version of netNIMA it belongs to, from the workspace's `Cargo.toml`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = concat!(
    "netnima-helper: the part of netNIMA that will hold the rights the app itself never asks for.\n",
    "It is started by netNIMA, not by hand.\n",
    "\n",
    "  netnima-helper --version   says its version",
);

/// What the helper says for these arguments, or why it cannot.
fn answer(args: &[String]) -> Result<String, String> {
    match args {
        [flag] if flag == "--version" || flag == "-V" => Ok(format!("netnima-helper {VERSION}")),
        [flag] if flag == "--help" || flag == "-h" => Ok(USAGE.to_string()),
        _ => Err(USAGE.to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match answer(&args) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(text) => {
            eprintln!("{text}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn it_says_its_version_as_the_app_reads_it() {
        let text = answer(&args(&["--version"])).unwrap();
        assert_eq!(text, format!("netnima-helper {VERSION}"));
        assert_eq!(answer(&args(&["-V"])).unwrap(), text);
    }

    #[test]
    fn anything_else_gets_how_to_use_it() {
        assert!(answer(&args(&[])).unwrap_err().contains("--version"));
        assert!(
            answer(&args(&["--capture"]))
                .unwrap_err()
                .contains("--version")
        );
        assert!(answer(&args(&["--version", "--version"])).is_err());
        assert!(answer(&args(&["--help"])).unwrap().contains("--version"));
    }
}
