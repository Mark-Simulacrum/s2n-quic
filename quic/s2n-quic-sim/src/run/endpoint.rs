// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{events, CliRange};
use s2n_quic::provider::dc::{ConfirmComplete, MtuConfirmComplete};
use s2n_quic::provider::tls;
use s2n_quic::{
    client::Connect,
    provider::{
        event::tracing::Subscriber as Tracing,
        io::testing::{primary, rand, spawn, time, Handle, Result},
    },
    Client, Server,
};
use s2n_quic_core::crypto::tls::testing::certificates;
use s2n_quic_core::endpoint::limits::Outcome;
use std::{net::SocketAddr, time::Duration};

struct Limiter;

impl s2n_quic::provider::endpoint_limits::Limiter for Limiter {
    fn on_connection_attempt(
        &mut self,
        info: &s2n_quic_core::endpoint::limits::ConnectionAttempt,
    ) -> Outcome {
        if info.inflight_handshakes > 100 {
            Outcome::drop()
        } else {
            Outcome::allow()
        }
    }
}

pub fn server(handle: &Handle, events: events::Events) -> Result<SocketAddr> {
    let server_tls = build_server_mtls_provider(certificates::MTLS_CA_CERT)?;
    let signer = s2n_quic_dc::path::secret::stateless_reset::Signer::new(b"TODO");
    let map = s2n_quic_dc::path::secret::Map::new(
        signer,
        10000,
        s2n_quic_core::time::clock::testing::Clock::default(),
        s2n_quic_dc::event::disabled::Subscriber::default(),
    );
    map.stop_cleaner_for_testing();
    let mut server = Server::builder()
        .with_io(
            handle
                .builder()
                .with_internal_recv_buffer_size(16 * 1024)?
                .with_base_mtu(1450)
                .with_initial_mtu(8940)
                .with_max_mtu(8940)
                .build()
                .unwrap(),
        )?
        .with_limits(
            s2n_quic::provider::limits::Limits::new()
                .with_initial_round_trip_time(Duration::from_millis(1))?,
        )?
        //.with_endpoint_limits(Limiter)?
        .with_dc(map.clone())?
        .with_tls(server_tls)?
        .with_event(((events, ConfirmComplete), Tracing::default()))?
        .start()?;
    let server_addr = server.local_addr()?;

    // accept connections and echo back
    spawn(async move {
        while let Some(mut connection) = server.accept().await {
            primary::spawn(async move {
                while let Ok(Some(mut stream)) = connection.accept_bidirectional_stream().await {
                    primary::spawn(async move {
                        while let Ok(Some(chunk)) = stream.receive().await {
                            let _ = chunk;
                        }
                    });
                }
            });
        }
    });

    Ok(server_addr)
}

pub fn client(
    handle: &Handle,
    events: events::Events,
    servers: &[SocketAddr],
    count: usize,
    delay: CliRange<jiff::SignedDuration>,
    _streams: CliRange<u32>,
    _stream_data: CliRange<u64>,
) -> Result {
    let signer = s2n_quic_dc::path::secret::stateless_reset::Signer::new(b"TODO");
    let map = s2n_quic_dc::path::secret::Map::new(
        signer,
        10,
        s2n_quic_core::time::clock::testing::Clock::default(),
        s2n_quic_dc::event::disabled::Subscriber::default(),
    );
    map.stop_cleaner_for_testing();
    let client_tls = build_client_mtls_provider(certificates::MTLS_CA_CERT)?;
    let client = Client::builder()
        .with_io(
            handle
                .builder()
                .with_internal_recv_buffer_size(16 * 1024)?
                .with_base_mtu(1450)
                .with_initial_mtu(8940)
                .with_max_mtu(8940)
                .build()
                .unwrap(),
        )?
        .with_limits(
            s2n_quic::provider::limits::Limits::new()
                .with_initial_round_trip_time(Duration::from_millis(1))?,
        )?
        .with_tls(client_tls)?
        .with_dc(map.clone())?
        .with_event(((events, ConfirmComplete), Tracing::default()))?
        .start()?;

    let mut total_delay = core::time::Duration::ZERO;

    for _ in 0..count {
        total_delay += delay.gen_duration();

        // pick a random server to connect to
        let server_addr = *rand::pick(servers);
        let delay = total_delay;

        let client = client.clone();
        primary::spawn(async move {
            if !delay.is_zero() {
                time::delay(delay).await;
            }

            let connect = Connect::new(server_addr).with_server_name("localhost");
            let mut connection = client.connect(connect).await?;

            time::timeout(
                Duration::from_secs(10),
                ConfirmComplete::wait_ready(&mut connection),
            )
            .await??;

            let _ = time::timeout(
                Duration::from_secs(10),
                MtuConfirmComplete::wait_ready(&mut connection),
            )
            .await;

            // Leave the connection open for 1 more second to allow the peer
            // to finish MTU probing as well
            time::delay(Duration::from_secs(1)).await;

            // for _ in 0..streams.gen() {
            //     let stream = connection.open_bidirectional_stream().await?;
            //     primary::spawn(async move {
            //         let (mut recv, mut send) = stream.split();

            //         let mut send_data = Data::new(stream_data.gen());

            //         let mut recv_data = send_data;
            //         primary::spawn(async move {
            //             while let Some(chunk) = recv.receive().await? {
            //                 recv_data.receive(&[chunk]);
            //             }

            //             <s2n_quic::stream::Result<()>>::Ok(())
            //         });

            //         while let Some(chunk) = send_data.send_one(usize::MAX) {
            //             send.send(chunk).await?;
            //         }

            //         <s2n_quic::stream::Result<()>>::Ok(())
            //     })
            //     .await
            //     .unwrap()?;
            // }

            <std::io::Result<()>>::Ok(())
        });
    }

    Ok(())
}

pub fn build_client_mtls_provider(ca_cert: &str) -> Result<tls::default::Client> {
    let tls = tls::default::Client::builder()
        .with_empty_trust_store()?
        .with_certificate(ca_cert)?
        .with_client_identity(
            certificates::MTLS_CLIENT_CERT,
            certificates::MTLS_CLIENT_KEY,
        )?
        .build()?;
    Ok(tls)
}

pub fn build_server_mtls_provider(ca_cert: &str) -> Result<tls::default::Server> {
    let tls = tls::default::Server::builder()
        .with_empty_trust_store()?
        .with_certificate(
            certificates::MTLS_SERVER_CERT,
            certificates::MTLS_SERVER_KEY,
        )?
        .with_client_authentication()?
        .with_trusted_certificate(ca_cert)?
        .build()?;
    Ok(tls)
}

mod slow_tls {
    use s2n_quic::provider::tls::Provider;
    use s2n_quic_core::crypto::tls::{slow_tls::SlowEndpoint, Endpoint};
    pub struct SlowTlsProvider<E: Endpoint> {
        pub tls: E,
    }

    impl<E: Endpoint> Provider for SlowTlsProvider<E> {
        type Server = SlowEndpoint<E>;
        type Client = SlowEndpoint<E>;
        type Error = String;

        fn start_server(self) -> Result<Self::Server, Self::Error> {
            Ok(SlowEndpoint::new(self.tls))
        }

        fn start_client(self) -> Result<Self::Client, Self::Error> {
            Ok(SlowEndpoint::new(self.tls))
        }
    }
}
