// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use criterion::{BenchmarkId, Criterion};
use s2n_quic::provider::limits;
use s2n_quic_core::inet::SocketAddressV4;
use s2n_quic_core::io::tx::PayloadBuffer;

struct TestIo {
    endpoint: Arc<Mutex<Option<Box<dyn EndpointWrapper>>>>,
}

struct Packet {
    handle: s2n_quic_core::path::Tuple,
    buffer: Vec<u8>,
}

struct Queue {
    packets: Vec<Packet>,
    buffers: Vec<Vec<u8>>,
}
impl Queue {
    fn new() -> Queue {
        Queue {
            packets: Vec::new(),
            buffers: vec![vec![0; 16384]; 10],
        }
    }
}

impl s2n_quic_core::io::rx::Queue for Queue {
    type Handle = s2n_quic_core::path::Tuple;

    fn for_each<F: FnMut(s2n_quic_core::inet::datagram::Header<Self::Handle>, &mut [u8])>(
        &mut self,
        mut on_packet: F,
    ) {
        for mut packet in self.packets.drain(..) {
            let handle = s2n_quic_core::path::Tuple {
                remote_address: s2n_quic_core::path::RemoteAddress(packet.handle.local_address.0),
                local_address: s2n_quic_core::path::LocalAddress(packet.handle.remote_address.0),
            };
            on_packet(
                s2n_quic_core::inet::datagram::Header {
                    path: handle,
                    ecn: s2n_quic_core::inet::ExplicitCongestionNotification::NotEct,
                },
                &mut packet.buffer,
            );
            self.buffers.push(packet.buffer);
        }
    }

    fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

impl s2n_quic_core::io::tx::Queue for Queue {
    type Handle = s2n_quic_core::path::Tuple;

    fn push<M: s2n_quic_core::io::tx::Message<Handle = Self::Handle>>(
        &mut self,
        mut message: M,
    ) -> Result<s2n_quic_core::io::tx::Outcome, s2n_quic_core::io::tx::Error> {
        let mut buffer = self.buffers.pop().unwrap_or_else(|| vec![0; 16384]);
        let wrote = message.write_payload(PayloadBuffer::new(&mut buffer), 0)?;
        assert_ne!(wrote, 0);
        buffer.truncate(wrote);
        let mut handle = message.path_handle().clone();
        if handle.local_address.port() == 0 {
            handle.local_address.set_port(1929);
        }
        self.packets.push(Packet { handle, buffer });
        Ok(s2n_quic_core::io::tx::Outcome {
            len: self.packets.len(),
            index: 0,
        })
    }

    fn capacity(&self) -> usize {
        usize::MAX
    }
}

trait EndpointWrapper {
    fn receive(&mut self, rx: &mut Queue);
    fn transmit(&mut self, tx: &mut Queue);
    fn wakeups(&mut self);
    fn full_event_loop(&mut self, rx_queue: &mut Queue, tx_queue: &mut Queue);
}

struct Wrapper<E> {
    endpoint: E,
}

impl<E: s2n_quic_core::endpoint::Endpoint<PathHandle = s2n_quic_core::path::Tuple>> EndpointWrapper
    for Wrapper<E>
{
    fn receive(&mut self, rx: &mut Queue) {
        assert!(!rx.packets.is_empty());
        self.endpoint.receive(rx, &s2n_quic_core::time::NoopClock);
    }

    fn transmit(&mut self, tx: &mut Queue) {
        self.endpoint.transmit(tx, &s2n_quic_core::time::NoopClock);
        assert!(!tx.packets.is_empty());
    }

    fn wakeups(&mut self) {
        let waker = dummy();
        let mut cx = std::task::Context::from_waker(&waker);
        let res = self
            .endpoint
            .poll_wakeups(&mut cx, &s2n_quic_core::time::NoopClock);
        if let Poll::Ready(Ok(count)) = res {
            assert_eq!(count, 1);
        } else {
            panic!("unexpected wakeups: {:?}", res);
        }
    }

    fn full_event_loop(&mut self, rx_queue: &mut Queue, tx_queue: &mut Queue) {
        // At most twice.
        for _ in 0..2 {
            let waker = dummy();
            let mut cx = std::task::Context::from_waker(&waker);
            let _ = self
                .endpoint
                .poll_wakeups(&mut cx, &s2n_quic_core::time::NoopClock);

            if !rx_queue.packets.is_empty() {
                self.endpoint
                    .receive(rx_queue, &s2n_quic_core::time::NoopClock);
            }

            let before = tx_queue.packets.len();
            self.endpoint
                .transmit(tx_queue, &s2n_quic_core::time::NoopClock);

            // The transmit() call itself is unconditional, but if it enqueues new packets then we'll
            // very likely need to go around again.
            if before == 0 && tx_queue.packets.is_empty() {
                return;
            }
        }
    }
}

impl s2n_quic::provider::io::Provider for TestIo {
    type PathHandle = s2n_quic_core::path::Tuple;
    type Error = String;

    fn start<E: s2n_quic_core::endpoint::Endpoint<PathHandle = Self::PathHandle>>(
        self,
        endpoint: E,
    ) -> Result<s2n_quic_core::inet::SocketAddress, Self::Error> {
        *self.endpoint.lock().unwrap() = Some(Box::new(Wrapper { endpoint }));
        Ok(s2n_quic_core::inet::SocketAddress::IpV4(
            SocketAddressV4::new(Ipv4Addr::new(127, 0, 0, 1), 3333),
        ))
    }
}

pub fn benchmarks(c: &mut Criterion) {
    tracing_subscriber::fmt::init();
    //pause(c);
    //channel_loopback(c);
    memory_loopback(c);
    //network_loopback(c);
}

fn pause(c: &mut Criterion) {
    c.bench_function("pause", |b| {
        b.iter(|| std::hint::spin_loop());
    });
}

fn channel_loopback(c: &mut Criterion) {
    c.bench_function("channel_loopback", |b| {
        let (c_out_tx, c_out_rx) = std::sync::mpsc::channel();
        let (c_in_tx, c_in_rx) = std::sync::mpsc::channel();
        let (s_in_tx, s_in_rx) = std::sync::mpsc::channel();

        let client_out = std::thread::spawn(move || {
            while let Ok(()) = c_out_rx.recv() {
                s_in_tx.send(()).unwrap();
            }
        });
        let server = std::thread::spawn(move || {
            while let Ok(()) = s_in_rx.recv() {
                c_in_tx.send(()).unwrap();
            }
        });

        b.iter(|| {
            c_out_tx.send(()).unwrap();
            c_in_rx.recv().unwrap();
        });

        drop(c_out_tx);
        client_out.join().unwrap();
        server.join().unwrap();
    });
}

fn memory_loopback(c: &mut Criterion) {
    // 35% slowdown from using full event loop.
    let use_full_event_loop = true;

    let io = TestIo {
        endpoint: std::sync::Arc::new(std::sync::Mutex::new(None)),
    };
    let server_endpoint = io.endpoint.clone();
    let mut server = s2n_quic::Server::builder()
        .with_congestion_controller(s2n_quic::provider::congestion_controller::Bbr::default())
        .unwrap()
        .with_io(io)
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
    let mut server_endpoint = server_endpoint.lock().unwrap().take().unwrap();

    let client_io = TestIo {
        endpoint: std::sync::Arc::new(std::sync::Mutex::new(None)),
    };
    let client_endpoint = client_io.endpoint.clone();
    let client = s2n_quic::Client::builder()
        .with_congestion_controller(s2n_quic::provider::congestion_controller::Bbr::default())
        .unwrap()
        .with_io(client_io)
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
    let mut client_endpoint = client_endpoint.lock().unwrap().take().unwrap();
    let mut client_tx = Queue::new();
    let mut server_tx = Queue::new();
    let dummy_waker = dummy();
    let mut cx = std::task::Context::from_waker(&dummy_waker);

    // Handshake a connection.
    let mut connection = std::pin::pin!(client.connect(
        s2n_quic::client::Connect::new("127.0.0.1:443".parse::<SocketAddr>().unwrap())
            .with_server_name("localhost")
    ));
    assert!(matches!(connection.as_mut().poll(&mut cx), Poll::Pending));
    client_endpoint.wakeups();
    client_endpoint.transmit(&mut client_tx);
    assert_eq!(client_tx.packets.len(), 1);
    server_endpoint.receive(&mut client_tx);
    server_endpoint.transmit(&mut server_tx);
    assert_eq!(server_tx.packets.len(), 1);
    client_endpoint.receive(&mut server_tx);
    client_endpoint.transmit(&mut client_tx);
    assert_eq!(client_tx.packets.len(), 1);
    server_endpoint.receive(&mut client_tx);
    let mut acceptor = std::pin::pin!(server.accept());
    let Poll::Ready(Some(mut server_conn)) = acceptor.as_mut().poll(&mut cx) else {
            panic!("Unexpectedly connection is not ready");
        };
    let Poll::Ready(Ok(mut client_conn)) = connection.as_mut().poll(&mut cx) else {
            panic!("Unexpectedly connection is not ready");
        };
    client_conn.keep_alive(true).unwrap();

    let mut group = c.benchmark_group("request_response/memory_loopback");
    for concurrent in [1, 2, 5, 30] {
        let payload_len = 100;
        let possible_request: &'static [u8] = &*vec![33; 1024 * 200].leak();
        group.bench_function(BenchmarkId::from_parameter(concurrent), |b| b.iter(|| {
            let mut streams = Vec::with_capacity(concurrent);
            for _ in 0..concurrent {
                // Stream open, send, and receive.
                let Poll::Ready(Ok(mut stream)) = client_conn.poll_open_bidirectional_stream(&mut cx) else {
                    panic!("Could not create stream");
                };
                let mut request = bytes::Bytes::from_static(&possible_request[..payload_len]);
                assert!(matches!(
                    stream.poll_send(&mut request, &mut cx),
                    Poll::Ready(Ok(()))
                ));
                streams.push(stream);
            }
            if use_full_event_loop {
                client_endpoint.full_event_loop(&mut server_tx, &mut client_tx);
            } else {
                client_endpoint.wakeups();
                client_endpoint.transmit(&mut client_tx);
            }
            {
                if use_full_event_loop {
                    server_endpoint.full_event_loop(&mut client_tx, &mut server_tx);
                } else {
                    server_endpoint.receive(&mut client_tx);
                }
                for _ in 0..concurrent {
                    let Poll::Ready(Ok(Some(mut stream))) = server_conn.poll_accept_bidirectional_stream(&mut cx) else {
                        panic!("Could not accept stream");
                    };
                    let Poll::Ready(Ok(Some(mut buffer))) = stream.poll_receive(&mut cx) else {
                        panic!("Could not get buffer from stream");
                    };
                    assert!(matches!(
                        stream.poll_send(&mut buffer, &mut cx),
                        Poll::Ready(Ok(()))
                    ));
                }
                if use_full_event_loop {
                    server_endpoint.full_event_loop(&mut client_tx, &mut server_tx);
                } else {
                    server_endpoint.transmit(&mut server_tx);
                }
            }
            if use_full_event_loop {
                client_endpoint.full_event_loop(&mut server_tx, &mut client_tx);
            } else {
                client_endpoint.receive(&mut server_tx);
            }

            for mut stream in streams {
                let Poll::Ready(Ok(Some(_))) = stream.poll_receive(&mut cx) else {
                    panic!("Could not get buffer from stream");
                };

                drop(stream);
            }

            // Take care of handling drop...
            if use_full_event_loop {
                client_endpoint.full_event_loop(&mut server_tx, &mut client_tx);
                server_endpoint.full_event_loop(&mut client_tx, &mut server_tx);
            } else {
                client_endpoint.wakeups();
                client_endpoint.transmit(&mut client_tx);
                server_endpoint.receive(&mut client_tx);
            }
        }));
    }
    group.finish();
}

fn network_loopback(c: &mut Criterion) {
    let client_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = std::thread::spawn(move || {
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
                .with_io("127.0.0.1:3000")
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
                let Poll::Ready(Ok(Some(mut buffer))) = stream.poll_receive(&mut cx) else {
                    panic!("Could not get buffer from stream");
                };
                assert!(matches!(
                    stream.poll_send(&mut buffer, &mut cx),
                    Poll::Ready(Ok(()))
                ));
            }
        });
    });
    let client_conn = client_rt.block_on(async move {
        let client = s2n_quic::Client::builder()
            .with_congestion_controller(s2n_quic::provider::congestion_controller::Bbr::default())
            .unwrap()
            .with_io("127.0.0.1:0")
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
                s2n_quic::client::Connect::new("127.0.0.1:3000".parse::<SocketAddr>().unwrap())
                    .with_server_name("localhost"),
            )
            .await
            .unwrap();
        client_conn
    });
    let rt = Arc::new(client_rt);
    let mut group = c.benchmark_group("request_response/network_loopback");
    for payload_len in [1, 10, 100, 1000] {
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
                    let _ = stream.receive().await;
                }
            })
        });
    }
    group.finish();

    drop(client_conn);
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
