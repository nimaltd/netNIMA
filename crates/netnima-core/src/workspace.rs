//! What is open in the window, kept in `workspace.toml`, so the app opens the
//! way it was left: the same tabs, in the same window.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::net::{TcpClientConfig, TcpServerConfig, UdpConfig};
use crate::tomlfile;

const HEADER: &str =
    "# netNIMA workspace: the tabs that were open. netNIMA writes it on every change.\n\n";

/// The smallest window size kept, inside its frame. A smaller one is from a
/// window that was minimized or not drawn yet, not one the user made.
const WINDOW_MIN: (u32, u32) = (320, 200);

/// One tab, as it is saved.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TabSetup {
    pub name: String,
    /// What the tab is: a protocol and its end, such as "mqtt_client" or
    /// "mqtt_server", or "udp", as the UI's `new-tab.ts` lists them. A word, not
    /// a fixed list here, so a tab from a newer netNIMA does not break the
    /// file: the UI leaves out the kinds it does not know.
    pub kind: String,
    /// Whether it was connected, or listening, when it was saved.
    pub connected: bool,
    /// What the tab shows: "terminal", "hex", "lines", "plot" or the protocol's own.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub view: String,
    /// Whether what it receives is written to a log file.
    #[serde(skip_serializing_if = "is_false")]
    pub log: bool,
    /// A UDP tab's socket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<UdpConfig>,
    /// A TCP or Telnet client's connection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_client: Option<TcpClientConfig>,
    /// A TCP or Telnet server's port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_server: Option<TcpServerConfig>,
    /// The recording a replay tab plays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplaySetup>,
    /// DTLS on a UDP tab's socket: a DTLS tab's, or a protocol's over DTLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dtls: Option<crate::net::DtlsOptions>,
    /// A protocol tab's own settings, such as an MQTT client's id, as its
    /// engine in `proto` reads them. Kept as it is.
    #[serde(skip_serializing_if = "toml::Table::is_empty")]
    pub protocol: toml::Table,
    /// What the UI keeps of the tab's views as it wrote it: the terminal's
    /// options, how the hex, lines and plot views show, and the send box's
    /// history. Kept as it is, so a newer UI's settings are not lost.
    #[serde(skip_serializing_if = "toml::Table::is_empty")]
    pub ui: toml::Table,
}

/// The recording a replay tab plays, and how fast.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplaySetup {
    pub path: String,
    pub speed: f64,
}

impl Default for ReplaySetup {
    fn default() -> Self {
        Self {
            path: String::new(),
            speed: 1.0,
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// The window's place and size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowState {
    /// The window's top left corner, its frame included.
    pub x: i32,
    pub y: i32,
    /// The size of the window's inside, its frame not included.
    pub width: u32,
    pub height: u32,
    /// Whether it filled the screen. The place and size above are then the
    /// ones it goes back to.
    #[serde(default)]
    pub maximized: bool,
}

/// The part of a screen windows can use, without the taskbar or the Dock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl WindowState {
    /// Whether enough of the window's title bar is on one of `screens` to
    /// grab it, so a window whose screen was unplugged is not put out of reach.
    pub fn reachable(&self, screens: &[Area]) -> bool {
        // The top 30 pixels of the window: at least 100 by 20 of them on one screen.
        screens.iter().any(|screen| {
            let left = self.x.max(screen.x);
            let right = (self.x + self.width as i32).min(screen.x + screen.width as i32);
            let top = self.y.max(screen.y);
            let bottom = (self.y + 30).min(screen.y + screen.height as i32);
            right - left >= 100 && bottom - top >= 20
        })
    }
}

/// Everything in `workspace.toml`. A value missing from the file takes its default.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Workspace {
    /// The tab in front, counted from 0.
    pub active: usize,
    /// The window's place and size when it last moved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<WindowState>,
    pub tabs: Vec<TabSetup>,
}

impl Workspace {
    /// Reads the workspace from `path`; see [`tomlfile::load`] for missing and broken files.
    pub fn load(path: &Path) -> Self {
        tomlfile::load::<Workspace>(path).checked()
    }

    /// Writes the workspace to `path`, safely; see [`tomlfile::save`].
    pub fn save(&self, path: &Path) -> io::Result<()> {
        tomlfile::save(self, path, HEADER)
    }

    /// The same workspace with the tab in front pointing at a tab that
    /// exists, and without a window size too small to be real.
    pub fn checked(mut self) -> Self {
        self.active = self.active.min(self.tabs.len().saturating_sub(1));
        self.window = self
            .window
            .filter(|window| window.width >= WINDOW_MIN.0 && window.height >= WINDOW_MIN.1);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::tomlfile::tests::TempDir;

    fn tab(name: &str, kind: &str) -> TabSetup {
        TabSetup {
            name: name.into(),
            kind: kind.into(),
            ..TabSetup::default()
        }
    }

    #[test]
    fn missing_file_gives_an_empty_workspace() {
        let dir = TempDir::new("workspace-missing");
        assert_eq!(
            Workspace::load(&dir.file("workspace.toml")),
            Workspace::default()
        );
    }

    #[test]
    fn saved_workspace_loads_back_the_same() {
        let dir = TempDir::new("workspace-round-trip");
        let path = dir.file("workspace.toml");
        let workspace = Workspace {
            active: 1,
            window: Some(WindowState {
                x: -1200,
                y: 40,
                width: 1200,
                height: 760,
                maximized: true,
            }),
            tabs: vec![
                tab("UDP", "udp"),
                TabSetup {
                    connected: true,
                    view: "mqtt".into(),
                    ..tab("MQTT broker", "mqtt_server")
                },
                tab("Capture", "capture"),
                TabSetup {
                    connected: true,
                    log: true,
                    udp: Some(UdpConfig {
                        local_port: 5683,
                        remote_host: "192.168.1.50".into(),
                        remote_port: 5683,
                        ..UdpConfig::default()
                    }),
                    ui: toml::from_str(
                        "[terminal]
enter = \"crlf\"
local_echo = true

[hex_view]
width = 16
",
                    )
                    .unwrap(),
                    ..tab("ESP32", "udp")
                },
                TabSetup {
                    tcp_server: Some(TcpServerConfig {
                        port: 2323,
                        telnet: true,
                        ..TcpServerConfig::default()
                    }),
                    ..tab("Shell server", "telnet_server")
                },
                TabSetup {
                    replay: Some(ReplaySetup {
                        path: "D:/logs/ESP32 2026-11-14 10-00-00.nrec".into(),
                        speed: 2.0,
                    }),
                    ..tab("Played", "replay")
                },
            ],
        };
        workspace.save(&path).unwrap();
        assert_eq!(Workspace::load(&path), workspace);
    }

    #[test]
    fn tabs_are_written_as_words() {
        let dir = TempDir::new("workspace-words");
        let path = dir.file("workspace.toml");
        let workspace = Workspace {
            tabs: vec![tab("CoAP client", "coap_client")],
            ..Workspace::default()
        };
        workspace.save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# netNIMA workspace"));
        assert!(text.contains("[[tabs]]"));
        assert!(text.contains("name = \"CoAP client\""));
        assert!(text.contains("kind = \"coap_client\""));
        // An empty view is left out.
        assert!(!text.contains("view"));
    }

    #[test]
    fn a_kind_from_a_newer_netnima_does_not_break_the_file() {
        let dir = TempDir::new("workspace-newer");
        let path = dir.file("workspace.toml");
        fs::write(
            &path,
            "[[tabs]]\nname = \"Later\"\nkind = \"from_the_future\"\nsetting = 3\n",
        )
        .unwrap();
        let workspace = Workspace::load(&path);
        assert_eq!(workspace.tabs, vec![tab("Later", "from_the_future")]);
        assert!(!dir.file("workspace.bad.toml").exists());
    }

    #[test]
    fn the_tab_in_front_is_one_that_exists() {
        let workspace = Workspace {
            active: 7,
            tabs: vec![tab("A", "udp"), tab("B", "tcp_client")],
            ..Workspace::default()
        };
        assert_eq!(workspace.checked().active, 1);
        let empty = Workspace {
            active: 3,
            ..Workspace::default()
        };
        assert_eq!(empty.checked().active, 0);
    }

    #[test]
    fn a_window_too_small_to_be_real_is_dropped() {
        let workspace = Workspace {
            window: Some(WindowState {
                x: 0,
                y: 0,
                width: 160,
                height: 28,
                maximized: false,
            }),
            ..Workspace::default()
        };
        assert_eq!(workspace.checked().window, None);
    }

    #[test]
    fn a_window_is_reachable_only_with_its_title_bar_on_a_screen() {
        let screen = Area {
            x: 0,
            y: 0,
            width: 1920,
            height: 1040,
        };
        let window = WindowState {
            x: 100,
            y: 100,
            width: 1200,
            height: 760,
            maximized: false,
        };
        assert!(window.reachable(&[screen]));
        // On a screen to the left that is not there any more.
        let gone = WindowState { x: -1500, ..window };
        assert!(!gone.reachable(&[screen]));
        // Only its bottom edge shows at the top of the screen.
        let above = WindowState { y: -740, ..window };
        assert!(!above.reachable(&[screen]));
    }
}
