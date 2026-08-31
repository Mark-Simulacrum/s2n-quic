// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handshake latency when post-quantum key exchange makes the first flight in either
//! direction too large for a PTO probe to carry.
//!
//! s2n-quic pads the first flight up to `initial_mtu` in order to validate it, so an
//! endpoint configured with an `initial_mtu` the path cannot carry loses that flight.
//! Recovery runs in probe mode, which is clamped to `MINIMUM_MAX_DATAGRAM_SIZE` (1200),
//! leaving ~1145 bytes for CRYPTO — so the question each case below asks is whether a
//! handshake flight still fits once it has to travel inside a 1200-byte probe. A classical
//! ClientHello (~271 bytes) always does; an ML-KEM one (~1503 bytes) does not.
//!
//! The configuration under test is the one s2n-quic-dc used to run with: `base_mtu` 1450,
//! `initial_mtu` and `max_mtu` 8940 (jumbo), and a 1ms initial RTT. dc has since disabled
//! MTU discovery entirely (`base_mtu` = `initial_mtu` = `max_mtu`, #3295) and enabled client
//! packet buffering (#3296), so it no longer triggers this; [`dc_mtu_config_is_unaffected`]
//! pins that down. The remaining cases keep the regression itself covered, because the
//! underlying behavior is still reachable by any application that configures an
//! `initial_mtu` above the real path MTU.
//!
//! The cases are:
//!
//! - [`ml_kem_client_hello_exceeds_pto_probe`]: the regression. A big PQ ClientHello does
//!   not fit in one probe, and the server's `Normal`-mode ACKs are padded to jumbo and
//!   dropped, so neither side can make progress until the server's own PTO fires. ~191ms
//!   versus ~10ms for classical.
//! - [`no_regression_when_path_supports_initial_mtu`]: the same configuration on a
//!   jumbo-capable path is identical for both policies at ~1 RTT. The size of the
//!   ClientHello is not the problem; padding above the path MTU is.
//! - [`dc_mtu_config_is_unaffected`]: with `initial_mtu` never above `base_mtu` on either
//!   endpoint, both policies complete in ~1 RTT.
//! - [`client_initial_mtu_at_base_avoids_pto_ladder`]: clamping only the client escapes the
//!   ladder, but the server's oversized flight still costs the PQ handshake one extra round
//!   trip (~5ms versus ~4ms).
//!
//! The asymmetry to keep in mind is `Normal` mode (padded up to `initial_mtu`, so
//! undeliverable here) versus probe mode (clamped, so deliverable), rather than anything
//! specific to the client or the server.

use super::*;
use s2n_quic::provider::tls::default::{self as tls, security};

/// s2n-quic-dc's `DEFAULT_BASE_MTU`.
const BASE_MTU: u16 = 1450;
/// s2n-quic-dc's `DEFAULT_MTU` on Linux.
const JUMBO_MTU: u16 = 8940;
/// s2n-quic-dc's `DEFAULT_INITIAL_RTT`.
const INITIAL_RTT: Duration = Duration::from_millis(1);

/// Round-trip time of the simulated path.
const RTT: Duration = Duration::from_millis(1);

/// A policy with no PQ key exchange, producing a ~271 byte ClientHello.
const CLASSICAL_POLICY: &str = "20240503";
/// A policy offering x25519_mlkem768, producing a ~1503 byte ClientHello.
const ML_KEM_POLICY: &str = "20250721";

/// The MTU configuration of a single endpoint, mirroring the io builder's setters.
#[derive(Clone, Copy)]
struct Mtu {
    base_mtu: u16,
    initial_mtu: u16,
    max_mtu: u16,
}

/// A conservative base with a jumbo initial and max, so the first flight is padded up to
/// `JUMBO_MTU`. This is what s2n-quic-dc ran before it disabled MTU discovery, and is still
/// what any application gets by configuring an `initial_mtu` the path cannot carry.
const JUMBO_INITIAL_MTU: Mtu = Mtu {
    base_mtu: BASE_MTU,
    initial_mtu: JUMBO_MTU,
    max_mtu: JUMBO_MTU,
};

/// s2n-quic-dc's configuration today: MTU discovery disabled, so it never sends a datagram
/// a 1450-byte path cannot carry.
const NO_MTU_DISCOVERY: Mtu = Mtu {
    base_mtu: BASE_MTU,
    initial_mtu: BASE_MTU,
    max_mtu: BASE_MTU,
};

/// One simulated handshake. Written out in full at each call site so that every knob a
/// case depends on is visible in the case itself.
#[derive(Clone, Copy)]
struct Scenario<'a> {
    /// s2n-tls security policy version, applied to both endpoints.
    policy_version: &'a str,
    /// Largest UDP payload the simulated network will deliver.
    path_mtu: u16,
    client_mtu: Mtu,
    server_mtu: Mtu,
}

impl Scenario<'_> {
    /// Runs the handshake and returns how long it took in simulated time.
    fn handshake_time(&self) -> Duration {
        let model = Model::default();
        model.set_max_udp_payload(self.path_mtu);
        model.set_delay(RTT / 2);

        let result = Arc::new(Mutex::new(None));
        let handshake = result.clone();

        let policy = security::Policy::from_version(self.policy_version).unwrap();
        let (client_mtu, server_mtu) = (self.client_mtu, self.server_mtu);

        test(model.clone(), |handle| {
            let server = tls::Server::from_loader({
                let mut builder = tls::config::Config::builder();
                builder
                    .enable_quic()?
                    .set_application_protocol_preference(["h3"])?
                    .set_security_policy(&policy)?
                    .load_pem(
                        certificates::CERT_PEM.as_bytes(),
                        certificates::KEY_PEM.as_bytes(),
                    )?;
                builder.build()?
            });

            let server = Server::builder()
                .with_io(
                    handle
                        .builder()
                        .with_base_mtu(server_mtu.base_mtu)
                        .with_initial_mtu(server_mtu.initial_mtu)
                        .with_max_mtu(server_mtu.max_mtu)
                        .build()?,
                )?
                .with_tls(server)?
                // The oversized first flight is dropped by the network, which this
                // harness would otherwise treat as a fatal event.
                .with_event(tracing_events(false, model.clone()))?
                .with_random(Random::with_seed(456))?
                .with_limits(
                    provider::limits::Limits::default()
                        .with_initial_round_trip_time(INITIAL_RTT)?,
                )?
                .start()?;

            let client = tls::Client::from_loader({
                let mut builder = tls::config::Config::builder();
                builder
                    .enable_quic()?
                    .set_application_protocol_preference(["h3"])?
                    .set_security_policy(&policy)?
                    .trust_pem(certificates::CERT_PEM.as_bytes())?;
                builder.build()?
            });

            let client = Client::builder()
                .with_io(
                    handle
                        .builder()
                        .with_base_mtu(client_mtu.base_mtu)
                        .with_initial_mtu(client_mtu.initial_mtu)
                        .with_max_mtu(client_mtu.max_mtu)
                        .build()?,
                )?
                .with_tls(client)?
                .with_event(tracing_events(false, model.clone()))?
                .with_random(Random::with_seed(456))?
                .with_limits(
                    provider::limits::Limits::default()
                        .with_initial_round_trip_time(INITIAL_RTT)?
                        // Mirrors dc's client, which buffers packets so that a handshake
                        // flight arriving before its keys can be derived is not dropped.
                        .with_packet_buffer_size(JUMBO_MTU.into())?,
                )?
                .start()?;

            let addr = start_server(server)?;

            primary::spawn(async move {
                let start = io::time::now();
                let connection = client
                    .connect(Connect::new(addr).with_server_name("localhost"))
                    .await;
                let elapsed = io::time::now() - start;
                *handshake.lock().unwrap() = Some((elapsed, connection.is_ok()));
            });

            Ok(addr)
        })
        .unwrap();

        let (elapsed, succeeded) = result.lock().unwrap().expect("handshake did not finish");
        assert!(succeeded, "handshake failed after {elapsed:?}");
        elapsed
    }
}

/// On a path that cannot carry the oversized first flight, an ML-KEM ClientHello takes far
/// longer to complete than a classical one, because no PTO probe can carry it and the
/// handshake waits out the client's PTO backoff ladder instead.
///
/// Each client probe delivers only a 1145-byte prefix of the 1503-byte ClientHello. The
/// server cannot report what it received, because its `Normal`-mode transmissions are padded
/// to `initial_mtu` too, so even a pure-ACK reply goes out as an 8912-byte datagram and is
/// dropped. Nothing is ever ACKed, so the client re-sends from offset 0 on every probe. In
/// the trace the client probes at 3, 9, 21, 45, 93 and 189ms — its PTO ladder of 3, 6, 12,
/// 24, 48, 96ms — and only when the server's own PTO fires at 189.5ms does a clamped,
/// deliverable ACK reach the client. It immediately sends `offset 1145..1503` and the
/// handshake completes at ~191ms. Because that total is a sum of PTO rungs rather than round
/// trips, it is two orders of magnitude larger than the RTT and barely moves when the RTT
/// changes.
#[test]
fn ml_kem_client_hello_exceeds_pto_probe() {
    // ~10ms: one PTO to recover the lost first flight in each direction.
    let classical = Scenario {
        policy_version: CLASSICAL_POLICY,
        path_mtu: 1500,
        client_mtu: JUMBO_INITIAL_MTU,
        server_mtu: JUMBO_INITIAL_MTU,
    }
    .handshake_time();

    // ~191ms: the client's PTO ladder has to reach its sixth expiry.
    let ml_kem = Scenario {
        policy_version: ML_KEM_POLICY,
        path_mtu: 1500,
        client_mtu: JUMBO_INITIAL_MTU,
        server_mtu: JUMBO_INITIAL_MTU,
    }
    .handshake_time();

    assert!(
        ml_kem > classical * 5,
        "expected a large ML-KEM regression, got classical={classical:?} ml_kem={ml_kem:?}"
    );
    assert!(
        ml_kem > Duration::from_millis(150),
        "expected the PTO backoff ladder to dominate, got {ml_kem:?}"
    );
}

/// The regression is caused by the first flight being padded above the path MTU, not by the
/// size of the ClientHello itself: when the path can carry the jumbo first flight, both
/// policies complete in a single round trip.
#[test]
fn no_regression_when_path_supports_initial_mtu() {
    let classical = Scenario {
        policy_version: CLASSICAL_POLICY,
        path_mtu: 9001,
        client_mtu: JUMBO_INITIAL_MTU,
        server_mtu: JUMBO_INITIAL_MTU,
    }
    .handshake_time();

    let ml_kem = Scenario {
        policy_version: ML_KEM_POLICY,
        path_mtu: 9001,
        client_mtu: JUMBO_INITIAL_MTU,
        server_mtu: JUMBO_INITIAL_MTU,
    }
    .handshake_time();

    assert_eq!(classical, ml_kem);
    assert!(ml_kem < RTT * 2, "expected ~1 RTT, got {ml_kem:?}");
}

/// s2n-quic-dc's configuration today is unaffected: with MTU discovery disabled on both
/// endpoints no first flight is padded above the path MTU, so nothing is lost and the PQ
/// handshake costs exactly what the classical one does.
///
/// This is the baseline the other cases are measured against — the regression is a property
/// of `initial_mtu` exceeding the path MTU, not of PQ key exchange.
#[test]
fn dc_mtu_config_is_unaffected() {
    let classical = Scenario {
        policy_version: CLASSICAL_POLICY,
        path_mtu: 1500,
        client_mtu: NO_MTU_DISCOVERY,
        server_mtu: NO_MTU_DISCOVERY,
    }
    .handshake_time();

    let ml_kem = Scenario {
        policy_version: ML_KEM_POLICY,
        path_mtu: 1500,
        client_mtu: NO_MTU_DISCOVERY,
        server_mtu: NO_MTU_DISCOVERY,
    }
    .handshake_time();

    assert_eq!(classical, ml_kem);
    assert!(ml_kem < RTT * 2, "expected ~1 RTT, got {ml_kem:?}");
}

/// Isolates the client half of the mitigation: the client's `initial_mtu` is lowered to
/// `base_mtu`, so it splits its ClientHello across two deliverable packets instead of one
/// oversized datagram, while the server keeps the jumbo configuration and still loses its own
/// first flight.
///
/// That is enough to escape the PTO ladder, but the ML-KEM handshake is still one round trip
/// behind the classical one: ~5ms versus ~4ms. The server never gets stuck the way the client
/// does above, because every client packet is deliverable, so its PTO probes are ACKed and
/// each one makes progress. The residual cost is the same "probe cannot carry the flight"
/// problem one level down: the ML-KEM ServerHello is 1178 bytes of Initial CRYPTO and a
/// 1200-byte probe carries only 1125 of them, so the 53-byte tail waits for the client's ACK
/// and goes out a round trip later. The certificate the server probed alongside it is
/// buffered rather than dropped while the client still lacks Handshake keys, so it is
/// replayed as soon as that tail arrives and costs nothing further. The classical server
/// flight fits entirely in the first probe, so it finishes a round trip sooner.
#[test]
fn client_initial_mtu_at_base_avoids_pto_ladder() {
    let client_mtu = Mtu {
        base_mtu: BASE_MTU,
        initial_mtu: BASE_MTU,
        max_mtu: JUMBO_MTU,
    };

    // ~4ms: 1 RTT plus one PTO for the server's dropped jumbo first flight.
    let classical = Scenario {
        policy_version: CLASSICAL_POLICY,
        path_mtu: 1500,
        client_mtu,
        server_mtu: JUMBO_INITIAL_MTU,
    }
    .handshake_time();

    // ~5ms: one further round trip for the tail of the server's oversized flight.
    let ml_kem = Scenario {
        policy_version: ML_KEM_POLICY,
        path_mtu: 1500,
        client_mtu,
        server_mtu: JUMBO_INITIAL_MTU,
    }
    .handshake_time();

    assert!(
        ml_kem > classical,
        "expected the server's oversized flight to still cost extra, \
         got classical={classical:?} ml_kem={ml_kem:?}"
    );
    // Well clear of the ~191ms PTO ladder: the pathological case is gone.
    assert!(
        ml_kem < Duration::from_millis(20),
        "expected the PTO ladder to be avoided, got {ml_kem:?}"
    );
}
