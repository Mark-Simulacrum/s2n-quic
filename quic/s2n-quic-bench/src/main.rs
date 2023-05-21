use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;

use criterion::{criterion_group, criterion_main};
use criterion::{BenchmarkId, Criterion};
use s2n_quic::provider::limits;

fn benchmarks(c: &mut Criterion) {
    let bind_addr = std::env::var("BIND_TO").unwrap().parse::<IpAddr>().unwrap();

    let client_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = std::thread::spawn(move || {
        if std::env::var_os("SERVER").is_none() {
            let server_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            server_rt.block_on(async move {
                let mut server = s2n_quic::Server::builder()
                    .with_congestion_controller(
                        s2n_quic::provider::congestion_controller::Bbr::default(),
                    )
                    .unwrap()
                    .with_io((bind_addr, 3000))
                    .unwrap()
                    .with_limits(
                        limits::Limits::new()
                            .with_max_open_local_bidirectional_streams(100_000_000)
                            .unwrap()
                            .with_max_open_remote_bidirectional_streams(100_000_000)
                            .unwrap()
                            .with_data_window(1 << 30)
                            .unwrap(),
                    )
                    .unwrap()
                    .with_tls((
                        s2n_quic_core::crypto::tls::testing::certificates::CERT_PEM,
                        s2n_quic_core::crypto::tls::testing::certificates::KEY_PEM,
                    ))
                    .unwrap()
                    .start()
                    .unwrap();

                let mut server_conn = server.accept().await.unwrap();

                let dummy = dummy();
                let mut cx = std::task::Context::from_waker(&dummy);
                while let Ok(Some(mut stream)) = server_conn.accept_bidirectional_stream().await {
                    while let Ok(Some(mut buffer)) = stream.receive().await {
                        assert!(matches!(
                            stream.poll_send(&mut buffer, &mut cx),
                            Poll::Ready(Ok(()))
                        ));
                    }
                    stream.finish().unwrap();
                }
            });
        }
    });

    if let Ok(server) = std::env::var("SERVER") {
        let client_conn = client_rt.block_on(async move {
            let client = s2n_quic::Client::builder()
                .with_congestion_controller(
                    s2n_quic::provider::congestion_controller::Bbr::default(),
                )
                .unwrap()
                .with_io((bind_addr, 0))
                .unwrap()
                .with_limits(
                    limits::Limits::new()
                        .with_max_open_local_bidirectional_streams(100_000_000)
                        .unwrap()
                        .with_max_open_remote_bidirectional_streams(100_000_000)
                        .unwrap()
                        .with_data_window(1 << 30)
                        .unwrap(),
                )
                .unwrap()
                .with_tls(s2n_quic_core::crypto::tls::testing::certificates::CERT_PEM)
                .unwrap()
                .start()
                .unwrap();

            // Handshake a connection.
            let client_conn = client
                .connect(
                    s2n_quic::client::Connect::new(server.parse::<SocketAddr>().unwrap())
                        .with_server_name("localhost"),
                )
                .await
                .unwrap();
            client_conn
        });
        let rt = Arc::new(client_rt);
        let mut group = c.benchmark_group("request_response/network_loopback");
        for payload_len in [1, 10, 100, 1000, 10_000, 20_000, 50_000, 190 * 1024] {
            let possible_request: &'static [u8] = &*vec![33; 1024 * 200].leak();
            let client_conn = client_conn.handle();
            let rt = rt.clone();
            group.bench_function(BenchmarkId::from_parameter(payload_len), move |b| {
            let client_conn = client_conn.clone();
            b.to_async(&*rt).iter(move || {
                let mut client_conn = client_conn.clone();
                async move {
                    let dummy = dummy();
                    let mut cx = std::task::Context::from_waker(&dummy);
                    // Stream open, send, and receive.
                    let Poll::Ready(Ok(mut stream)) = client_conn.poll_open_bidirectional_stream(&mut cx) else {
                        panic!("Could not create stream");
                    };
                    let mut request = bytes::Bytes::from_static(&possible_request[..payload_len]);
                    assert!(matches!(
                        stream.poll_send(&mut request, &mut cx),
                        Poll::Ready(Ok(()))
                    ));
                    stream.finish().unwrap();
                    while let Ok(Some(_buffer)) = stream.receive().await { }
                }
            })
        });
        }
        group.finish();
        drop(client_conn);
    }

    server.join().unwrap();
}

static VTABLE: std::task::RawWakerVTable = std::task::RawWakerVTable::new(
    |_| -> std::task::RawWaker { std::task::RawWaker::new(std::ptr::null(), &VTABLE) },
    |_| {},
    |_| {},
    |_| {},
);

fn dummy() -> std::task::Waker {
    unsafe { std::task::Waker::from_raw(std::task::RawWaker::new(std::ptr::null(), &VTABLE)) }
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
