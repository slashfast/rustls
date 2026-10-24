//! Target-shaped REALITY flights with the ring provider.

#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::ServerName;
use rustls::reality::{FlightPlan, PreparedServerHello};
use rustls::{ClientConnection, ServerConfig, ServerConnection};
use rustls_test::{KeyType, do_handshake, make_client_config_with_versions};

fn target_hello(provider: &CryptoProvider) -> (ClientConnection, ServerConfig, Vec<u8>, Vec<u8>) {
    let config =
        make_client_config_with_versions(KeyType::Ed25519, &[&rustls::version::TLS13], provider);
    let server_config = rustls_test::make_server_config_with_versions(
        KeyType::Ed25519,
        &[&rustls::version::TLS13],
        provider,
    );
    let mut client =
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut target = ServerConnection::new(Arc::new(server_config.clone())).unwrap();
    let mut wire = Vec::new();
    client.write_tls(&mut wire).unwrap();
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        assert!(target.read_tls(&mut remaining).unwrap() > 0);
        target.process_new_packets().unwrap();
    }
    let mut response = Vec::new();
    target.write_tls(&mut response).unwrap();
    let len = u16::from_be_bytes([response[3], response[4]]) as usize;
    (client, server_config, wire, response[5..5 + len].to_vec())
}

fn record_lengths(wire: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut remaining = wire;
    while !remaining.is_empty() {
        let len = 5 + u16::from_be_bytes([remaining[3], remaining[4]]) as usize;
        lengths.push(len);
        remaining = &remaining[len..];
    }
    lengths
}

#[test]
fn ring_shaped_flights_preserve_record_lengths_and_application_key_epoch() {
    for suite in ring::default_provider()
        .cipher_suites
        .into_iter()
        .filter(|s| s.tls13().is_some())
    {
        for lengths in [vec![4096], vec![64, 4096, 128, 80]] {
            for trailing in [None, Some(128)] {
                let provider = CryptoProvider {
                    cipher_suites: vec![suite],
                    ..ring::default_provider()
                };
                let (mut client, config, client_wire, template) = target_hello(&provider);
                let plan = FlightPlan::new(&lengths, trailing).unwrap();
                let prepared = PreparedServerHello::new(&client_wire[5..], &template, &provider)
                    .unwrap()
                    .with_flight_plan(plan);
                let mut server = ServerConnection::new_reality(Arc::new(config), prepared).unwrap();
                let mut remaining = client_wire.as_slice();
                while !remaining.is_empty() {
                    assert!(server.read_tls(&mut remaining).unwrap() > 0);
                    server.process_new_packets().unwrap();
                }
                let mut wire = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut wire).unwrap();
                }
                let mut expected = vec![template.len() + 5, 6];
                expected.extend(&lengths);
                expected.extend(trailing);
                assert_eq!(record_lengths(&wire), expected, "{suite:?}");
                let mut remaining = wire.as_slice();
                while !remaining.is_empty() {
                    assert!(client.read_tls(&mut remaining).unwrap() > 0);
                    client.process_new_packets().unwrap();
                }
                do_handshake(&mut client, &mut server);
                server.refresh_traffic_keys().unwrap();
                server
                    .writer()
                    .write_all(b"after key update")
                    .unwrap();
                rustls_test::transfer(&mut server, &mut client);
                client.process_new_packets().unwrap();
                let mut received = [0; 16];
                client
                    .reader()
                    .read_exact(&mut received)
                    .unwrap();
                assert_eq!(&received, b"after key update");
            }
        }
    }
}

/// Without a flight plan the ring provider must produce exactly what it did
/// before padding existed: zero padding takes the ordinary encryption path.
#[test]
fn ring_unshaped_reality_flight_is_unpadded() {
    let provider = ring::default_provider();
    let (mut client, config, client_wire, template) = target_hello(&provider);
    let prepared = PreparedServerHello::new(&client_wire[5..], &template, &provider).unwrap();
    let mut server = ServerConnection::new_reality(Arc::new(config), prepared).unwrap();
    let mut remaining = client_wire.as_slice();
    while !remaining.is_empty() {
        assert!(server.read_tls(&mut remaining).unwrap() > 0);
        server.process_new_packets().unwrap();
    }
    let mut wire = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut wire).unwrap();
    }
    let mut remaining = wire.as_slice();
    while !remaining.is_empty() {
        assert!(client.read_tls(&mut remaining).unwrap() > 0);
        client.process_new_packets().unwrap();
    }
    do_handshake(&mut client, &mut server);
}
