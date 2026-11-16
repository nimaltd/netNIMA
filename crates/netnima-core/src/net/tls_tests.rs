//! TLS end to end: netNIMA's client against its server, on the loopback.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use super::tests::{AT_ONCE, FAST, SLOW_POLL, expect, joined, received, state};
use super::tls::{ClientAuth, Engine, TlsClientOptions, TlsServerOptions, Verify, Versions};
use super::{
    Agreed, Event, NetState, Target, TcpClient, TcpClientConfig, TcpServer, TcpServerConfig, Timing,
};
use crate::certs::{self, SetRequest};

fn server(tls: TlsServerOptions) -> (TcpServer, Receiver<Event>, u16) {
    server_timed(tls, FAST)
}

fn server_timed(tls: TlsServerOptions, timing: Timing) -> (TcpServer, Receiver<Event>, u16) {
    let (sender, events) = mpsc::channel();
    let server = TcpServer::start_with(
        TcpServerConfig {
            address: "127.0.0.1".into(),
            port: 0,
            tls: Some(tls),
            ..TcpServerConfig::default()
        },
        Box::new(move |event| {
            let _ = sender.send(event);
        }),
        timing,
    );
    let NetState::Listening { local } = state(&events, "listening", |state| {
        matches!(state, NetState::Listening { .. })
    }) else {
        unreachable!()
    };
    let port = local.rsplit(':').next().unwrap().parse().unwrap();
    (server, events, port)
}

fn client(port: u16, tls: TlsClientOptions) -> (TcpClient, Receiver<Event>) {
    client_timed(port, tls, FAST)
}

fn client_timed(port: u16, tls: TlsClientOptions, timing: Timing) -> (TcpClient, Receiver<Event>) {
    let (sender, events) = mpsc::channel();
    let client = TcpClient::start_with(
        TcpClientConfig {
            host: "127.0.0.1".into(),
            port,
            reconnect: false,
            tls: Some(tls),
            ..TcpClientConfig::default()
        },
        Box::new(move |event| {
            let _ = sender.send(event);
        }),
        timing,
    );
    (client, events)
}

#[test]
fn records_go_out_at_once_over_both_engines() {
    for engine in [Engine::Rustls, Engine::Openssl] {
        let (server, server_events, port) = server_timed(
            TlsServerOptions {
                engine,
                ..TlsServerOptions::default()
            },
            SLOW_POLL,
        );
        let (client, client_events) = client_timed(
            port,
            TlsClientOptions {
                engine,
                ..unchecked()
            },
            SLOW_POLL,
        );
        // Sent before the handshake ends: it goes when it does.
        client.write(b"early".to_vec());
        let peer = joined(&server_events);
        let me = joined(&client_events);
        assert_eq!(received(&server_events, peer.id, 5), b"early", "{engine:?}");
        // Both threads are in their long waits: each write has to wake one.
        thread::sleep(Duration::from_millis(50));
        for _ in 0..3 {
            let start = Instant::now();
            client.write(b"up".to_vec());
            assert_eq!(received(&server_events, peer.id, 2), b"up");
            server.write(Target::Peer(peer.id), b"down".to_vec());
            assert_eq!(received(&client_events, me.id, 4), b"down");
            assert!(
                start.elapsed() < AT_ONCE,
                "{engine:?}: {:?}",
                start.elapsed()
            );
        }
    }
}

fn secure(events: &Receiver<Event>) -> Agreed {
    match expect(events, "TLS", |event| matches!(event, Event::Secure { .. })) {
        Event::Secure { agreed, .. } => agreed,
        _ => unreachable!(),
    }
}

/// Why the client's connection ended.
fn ended(events: &Receiver<Event>) -> String {
    match state(events, "end", |state| {
        matches!(state, NetState::Ended { .. })
    }) {
        NetState::Ended { problem } => problem.unwrap_or_default(),
        _ => unreachable!(),
    }
}

fn unchecked() -> TlsClientOptions {
    TlsClientOptions {
        verify: Verify::None,
        ..TlsClientOptions::default()
    }
}

#[test]
fn a_tls_client_and_server_agree_and_pass_data_both_ways() {
    let (server, server_events, port) = server(TlsServerOptions {
        alpn: "mqtt".into(),
        ..TlsServerOptions::default()
    });
    let (client, client_events) = client(
        port,
        TlsClientOptions {
            alpn: "mqtt".into(),
            ..unchecked()
        },
    );
    let peer = joined(&server_events);
    // The connection comes first, then what TLS agreed on it.
    let me = joined(&client_events);
    let agreed = secure(&client_events);
    assert_eq!(agreed.version, "TLS 1.3");
    assert_eq!(agreed.alpn, "mqtt");
    assert!(agreed.suite.starts_with("TLS13_"), "{agreed:?}");
    assert_eq!(agreed.chain.len(), 1);
    assert!(agreed.chain[0].names.contains(&"127.0.0.1".to_string()));
    let seen = secure(&server_events);
    assert!(seen.chain.is_empty(), "the client sent no certificate");

    client.write(b"hello over TLS".to_vec());
    assert_eq!(received(&server_events, peer.id, 14), b"hello over TLS");
    server.write(Target::Peer(peer.id), b"and back".to_vec());
    assert_eq!(received(&client_events, me.id, 8), b"and back");
}

#[test]
fn a_lot_of_data_goes_through_tls_whole() {
    let (server, server_events, port) = server(TlsServerOptions::default());
    let (_client, client_events) = client(port, unchecked());
    let peer = joined(&server_events);
    let me = joined(&client_events);
    secure(&client_events);
    let data: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
    server.write(Target::Peer(peer.id), data.clone());
    assert_eq!(received(&client_events, me.id, data.len()), data);
}

#[test]
fn tls_1_2_can_be_asked_for() {
    let (_server, _events, port) = server(TlsServerOptions::default());
    let (_client, client_events) = client(
        port,
        TlsClientOptions {
            versions: Versions::Tls12,
            ..unchecked()
        },
    );
    let agreed = secure(&client_events);
    assert_eq!(agreed.version, "TLS 1.2");
    assert!(agreed.suite.starts_with("TLS_ECDHE_ECDSA"), "{agreed:?}");
}

#[test]
fn a_certificate_not_trusted_is_said_in_words() {
    let (_server, _events, port) = server(TlsServerOptions::default());
    let folder = certs::tests::scratch("untrusted");
    certs::make_set(&SetRequest {
        folder: folder.display().to_string(),
        ..SetRequest::default()
    })
    .unwrap();
    // Trusts another CA than the one that made the server's certificate.
    let (_client, client_events) = client(
        port,
        TlsClientOptions {
            verify: Verify::File,
            ca_file: folder.join("ca.crt").display().to_string(),
            ..TlsClientOptions::default()
        },
    );
    let problem = ended(&client_events);
    assert!(
        problem.contains("not signed by one this end trusts"),
        "{problem}"
    );
    let _ = std::fs::remove_dir_all(folder);
}

#[test]
fn a_set_made_here_works_both_ways_with_client_certificates() {
    let folder = certs::tests::scratch("both-ways");
    certs::make_set(&SetRequest {
        folder: folder.display().to_string(),
        server_names: vec!["board.local".into(), "127.0.0.1".into()],
        client_name: "sensor-7".into(),
        years: 1,
    })
    .unwrap();
    let file = |name: &str| folder.join(name).display().to_string();
    let (_server, server_events, port) = server(TlsServerOptions {
        cert_file: file("server.crt"),
        key_file: file("server.key"),
        client_auth: ClientAuth::Required,
        ca_file: file("ca.crt"),
        ..TlsServerOptions::default()
    });

    // Checked by name and CA, with the client's own certificate.
    let (_client, client_events) = client(
        port,
        TlsClientOptions {
            verify: Verify::File,
            ca_file: file("ca.crt"),
            cert_file: file("client.crt"),
            key_file: file("client.key"),
            ..TlsClientOptions::default()
        },
    );
    let agreed = secure(&client_events);
    assert!(
        agreed.chain[0].subject.contains("board.local"),
        "{agreed:?}"
    );
    assert!(agreed.chain[0].names.contains(&"127.0.0.1".to_string()));
    let seen = secure(&server_events);
    assert!(seen.chain[0].subject.contains("sensor-7"), "{seen:?}");

    // Without a certificate the server turns the client away.
    let (_bare, bare_events) = client(
        port,
        TlsClientOptions {
            verify: Verify::File,
            ca_file: file("ca.crt"),
            ..TlsClientOptions::default()
        },
    );
    let problem = ended(&bare_events);
    assert!(problem.contains("certificate"), "{problem}");

    // A name the certificate is not for is turned down, unless names are not checked.
    let wrong_name = TlsClientOptions {
        verify: Verify::File,
        ca_file: file("ca.crt"),
        server_name: "other.local".into(),
        cert_file: file("client.crt"),
        key_file: file("client.key"),
        ..TlsClientOptions::default()
    };
    let (_named, named_events) = client(port, wrong_name.clone());
    let problem = ended(&named_events);
    assert!(problem.contains("not for other.local"), "{problem}");
    let (_unnamed, unnamed_events) = client(
        port,
        TlsClientOptions {
            check_name: false,
            ..wrong_name
        },
    );
    secure(&unnamed_events);
    let _ = std::fs::remove_dir_all(folder);
}

#[test]
fn a_client_that_does_not_speak_tls_is_told_apart() {
    let (_server, server_events, port) = server(TlsServerOptions::default());
    let mut plain = TcpStream::connect(("127.0.0.1", port)).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    joined(&server_events);
    plain.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let problem = match expect(&server_events, "problem", |event| {
        matches!(event, Event::Problem(_))
    }) {
        Event::Problem(problem) => problem,
        _ => unreachable!(),
    };
    assert!(problem.contains("speak TLS"), "{problem}");
    let mut buf = [0; 64];
    // An alert, then the end.
    let _ = plain.read(&mut buf);
}

mod openssl_engine {
    use super::*;
    use crate::net::tls::Engine;

    fn old_server(versions: Versions) -> TlsServerOptions {
        TlsServerOptions {
            versions,
            engine: Engine::Openssl,
            ..TlsServerOptions::default()
        }
    }

    fn old_client(versions: Versions) -> TlsClientOptions {
        TlsClientOptions {
            versions,
            engine: Engine::Openssl,
            ..unchecked()
        }
    }

    #[test]
    fn tls_1_0_and_1_1_are_spoken() {
        for (versions, name) in [(Versions::Tls10, "TLS 1.0"), (Versions::Tls11, "TLS 1.1")] {
            let (server_end, server_events, port) = server(old_server(Versions::All));
            let (client_end, client_events) = client(port, old_client(versions));
            let peer = joined(&server_events);
            let me = joined(&client_events);
            let agreed = secure(&client_events);
            assert_eq!(agreed.version, format!("{name} (OpenSSL)"), "{agreed:?}");
            assert_eq!(agreed.chain.len(), 1, "{agreed:?}");
            client_end.write(b"old".to_vec());
            assert_eq!(received(&server_events, peer.id, 3), b"old");
            server_end.write(Target::Peer(peer.id), b"still".to_vec());
            assert_eq!(received(&client_events, me.id, 5), b"still");
        }
    }

    #[test]
    fn a_psk_connects_in_tls_1_2_and_1_3() {
        for (versions, suite) in [(Versions::Tls12, "PSK"), (Versions::Tls13, "TLS_AES")] {
            let (server_end, server_events, port) = server(TlsServerOptions {
                psk: true,
                psk_identity: String::new(),
                psk_key: "0102030405060708".into(),
                ..old_server(Versions::All)
            });
            let (client_end, client_events) = client(
                port,
                TlsClientOptions {
                    psk: true,
                    psk_identity: "sensor-7".into(),
                    psk_key: "0102030405060708".into(),
                    ..old_client(versions)
                },
            );
            let peer = joined(&server_events);
            let agreed = secure(&client_events);
            assert!(agreed.suite.contains(suite), "{agreed:?}");
            let seen = secure(&server_events);
            assert_eq!(seen.name, "PSK identity sensor-7", "{seen:?}");
            client_end.write(b"psk".to_vec());
            assert_eq!(received(&server_events, peer.id, 3), b"psk");
            drop(server_end);
        }
    }

    #[test]
    fn a_wrong_psk_is_said_in_words() {
        let (_server, _server_events, port) = server(TlsServerOptions {
            psk: true,
            psk_key: "0102030405060708".into(),
            ..old_server(Versions::Tls12)
        });
        let (_client, client_events) = client(
            port,
            TlsClientOptions {
                psk: true,
                psk_key: "ffffffffffffffff".into(),
                ..old_client(Versions::Tls12)
            },
        );
        let problem = ended(&client_events);
        assert!(problem.contains("The PSK was turned down"), "{problem}");
    }

    #[test]
    fn a_ccm_suite_can_be_asked_for() {
        let (_server, _server_events, port) = server(old_server(Versions::All));
        let (_client, client_events) = client(
            port,
            TlsClientOptions {
                ciphers: "ECDHE-ECDSA-AES128-CCM8".into(),
                ..old_client(Versions::Tls12)
            },
        );
        let agreed = secure(&client_events);
        assert_eq!(
            agreed.suite, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
            "{agreed:?}"
        );
    }

    #[test]
    fn each_engine_talks_to_the_other() {
        // rustls against OpenSSL, then OpenSSL against rustls.
        let (old_end, server_events, port) = server(old_server(Versions::Both));
        let (new_end, client_events) = client(port, unchecked());
        let peer = joined(&server_events);
        let agreed = secure(&client_events);
        assert_eq!(agreed.version, "TLS 1.3");
        new_end.write(b"to openssl".to_vec());
        assert_eq!(received(&server_events, peer.id, 10), b"to openssl");
        drop((old_end, new_end));

        let (new_server, server_events, port) = server(TlsServerOptions::default());
        let (old_client_end, client_events) = client(port, old_client(Versions::Both));
        let peer = joined(&server_events);
        let agreed = secure(&client_events);
        assert_eq!(agreed.version, "TLS 1.3 (OpenSSL)");
        old_client_end.write(b"to rustls".to_vec());
        assert_eq!(received(&server_events, peer.id, 9), b"to rustls");
        drop(new_server);
    }

    #[test]
    fn old_versions_pick_openssl_by_themselves() {
        let (_server, _server_events, port) = server(TlsServerOptions {
            versions: Versions::All,
            ..TlsServerOptions::default()
        });
        let (_client, client_events) = client(
            port,
            TlsClientOptions {
                versions: Versions::Tls10,
                ..unchecked()
            },
        );
        assert_eq!(secure(&client_events).version, "TLS 1.0 (OpenSSL)");
    }
}
