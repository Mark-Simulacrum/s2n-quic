use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Poll, Waker};
use std::sync::Arc;
use std::task::Wake;

use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_channel::oneshot::{Receiver, Sender};
use futures_core::Stream as _;

use crate::crypto::CryptoSuite;

use super::{Context, Endpoint, Session};

pub struct OffloadEndpoint<E: Endpoint> {
    new_stream: UnboundedSender<(E::Session, UnboundedSender<Request<E::Session>>)>,
    _thread: std::thread::JoinHandle<()>,
    inner: E,
    remote_thread: Waker,
}

impl<E: Endpoint + Default> Default for OffloadEndpoint<E> {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<E: Endpoint> OffloadEndpoint<E> {
    pub fn new(inner: E) -> OffloadEndpoint<E> {
        let (tx, mut rx) =
            futures_channel::mpsc::unbounded::<(E::Session, UnboundedSender<Request<E::Session>>)>(
            );
        let handle = std::thread::spawn(move || {
            let mut sessions = vec![];
            let waker = make_waker();
            loop {
                // accept new sessions
                let mut cx = std::task::Context::from_waker(&waker);
                while let Poll::Ready(Some((new_stream, tx))) = Pin::new(&mut rx).poll_next(&mut cx)
                {
                    sessions.push((
                        new_stream,
                        RemoteContext {
                            tx,
                            waker: waker.clone(),

                            receive_initial: AsyncRequest::empty(),
                            receive_handshake: AsyncRequest::empty(),
                            receive_application: AsyncRequest::empty(),

                            can_send_initial: AsyncRequest::empty(),
                            can_send_handshake: AsyncRequest::empty(),
                            can_send_application: AsyncRequest::empty(),
                        },
                    ));
                }

                tracing::trace!("polling {} sessions", sessions.len());

                let mut next_sessions = vec![];
                for (mut stream, mut ctx) in sessions {
                    match stream.poll(&mut ctx) {
                        core::task::Poll::Ready(res) => {
                            ctx.tx.unbounded_send(Request::Done(stream, res)).unwrap();
                        }
                        core::task::Poll::Pending => {
                            next_sessions.push((stream, ctx));
                        }
                    }
                }
                sessions = next_sessions;

                std::thread::park();
            }
        });
        Self {
            remote_thread: core::task::Waker::from(Arc::new(ThreadWaker(handle.thread().clone()))),
            _thread: handle,
            new_stream: tx,
            inner,
        }
    }
}

struct ThreadWaker(std::thread::Thread);

impl Wake for ThreadWaker {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.unpark();
    }
}

fn make_waker() -> core::task::Waker {
    core::task::Waker::from(Arc::new(ThreadWaker(std::thread::current())))
}

/// Context used on the remote thread. This must delegate all methods via a channel to the calling
/// thread, using `Request` to send parameters (and optionally receive results).
///
/// Note that because methods are not poll* based results may be associated with some delay (and
/// plausibly in a different order).
struct RemoteContext<S: CryptoSuite> {
    tx: UnboundedSender<Request<S>>,
    waker: core::task::Waker,

    receive_initial: AsyncRequest<Option<bytes::Bytes>>,
    receive_handshake: AsyncRequest<Option<bytes::Bytes>>,
    receive_application: AsyncRequest<Option<bytes::Bytes>>,

    can_send_initial: AsyncRequest<bool>,
    can_send_handshake: AsyncRequest<bool>,
    can_send_application: AsyncRequest<bool>,
}

impl<C, S2, K1, K2, K3, K4, K5, K6, K7, K8, K9> Context<C> for RemoteContext<S2>
where
    C: CryptoSuite<
        HandshakeKey = K1,
        HandshakeHeaderKey = K2,
        InitialKey = K3,
        InitialHeaderKey = K4,
        OneRttKey = K5,
        OneRttHeaderKey = K6,
        ZeroRttKey = K7,
        ZeroRttHeaderKey = K8,
        RetryKey = K9,
    >,
    S2: CryptoSuite<
        HandshakeKey = K1,
        HandshakeHeaderKey = K2,
        InitialKey = K3,
        InitialHeaderKey = K4,
        OneRttKey = K5,
        OneRttHeaderKey = K6,
        ZeroRttKey = K7,
        ZeroRttHeaderKey = K8,
        RetryKey = K9,
    >,
{
    fn on_client_application_params(
        &mut self,
        client_params: super::ApplicationParameters,
        server_params: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), crate::transport::Error> {
        let _ = self.tx.unbounded_send(Request::ClientAppParams(
            client_params.transport_parameters.to_vec(),
            server_params.clone(),
        ));
        Ok(())
    }

    fn on_handshake_keys(
        &mut self,
        key: <C as CryptoSuite>::HandshakeKey,
        header_key: <C as CryptoSuite>::HandshakeHeaderKey,
    ) -> Result<(), crate::transport::Error> {
        let _ = self
            .tx
            .unbounded_send(Request::HandshakeKeys(key, header_key));
        Ok(())
    }

    fn on_zero_rtt_keys(
        &mut self,
        key: <C as CryptoSuite>::ZeroRttKey,
        header_key: <C as CryptoSuite>::ZeroRttHeaderKey,
        application_parameters: super::ApplicationParameters,
    ) -> Result<(), crate::transport::Error> {
        let super::ApplicationParameters {
            transport_parameters,
        } = application_parameters;
        let _ = self.tx.unbounded_send(Request::ZeroRttKeys(
            key,
            header_key,
            transport_parameters.to_vec(),
        ));
        Ok(())
    }

    fn on_one_rtt_keys(
        &mut self,
        key: <C as CryptoSuite>::OneRttKey,
        header_key: <C as CryptoSuite>::OneRttHeaderKey,
        application_parameters: super::ApplicationParameters,
    ) -> Result<(), crate::transport::Error> {
        let super::ApplicationParameters {
            transport_parameters,
        } = application_parameters;
        let _ = self.tx.unbounded_send(Request::OneRttKeys(
            key,
            header_key,
            transport_parameters.to_vec(),
        ));
        Ok(())
    }

    fn on_server_name(
        &mut self,
        server_name: crate::application::ServerName,
    ) -> Result<(), crate::transport::Error> {
        let _ = self.tx.unbounded_send(Request::ServerName(server_name));
        Ok(())
    }

    fn on_application_protocol(
        &mut self,
        application_protocol: bytes::Bytes,
    ) -> Result<(), crate::transport::Error> {
        let _ = self
            .tx
            .unbounded_send(Request::ApplicationProtocol(application_protocol));
        Ok(())
    }

    fn on_handshake_complete(&mut self) -> Result<(), crate::transport::Error> {
        let _ = self.tx.unbounded_send(Request::HandshakeComplete);
        Ok(())
    }

    fn on_tls_exporter_ready(
        &mut self,
        _session: &impl super::TlsSession,
    ) -> Result<(), crate::transport::Error> {
        // FIXME: needs some form of async callback, or maybe never gets called during remote phase?
        Ok(())
    }

    fn receive_initial(&mut self, max_len: Option<usize>) -> Option<bytes::Bytes> {
        let mut cx = core::task::Context::from_waker(&self.waker);
        if let Poll::Ready(resp) = self.receive_initial.poll_request(&mut cx, |tx| {
            let _ = self.tx.unbounded_send(Request::ReceiveInitial(max_len, tx));
        }) {
            resp
        } else {
            None
        }
    }

    fn receive_handshake(&mut self, max_len: Option<usize>) -> Option<bytes::Bytes> {
        let mut cx = core::task::Context::from_waker(&self.waker);
        if let Poll::Ready(resp) = self.receive_handshake.poll_request(&mut cx, |tx| {
            let _ = self
                .tx
                .unbounded_send(Request::ReceiveHandshake(max_len, tx));
        }) {
            resp
        } else {
            None
        }
    }

    fn receive_application(&mut self, max_len: Option<usize>) -> Option<bytes::Bytes> {
        let mut cx = core::task::Context::from_waker(&self.waker);
        if let Poll::Ready(resp) = self.receive_application.poll_request(&mut cx, |tx| {
            let _ = self
                .tx
                .unbounded_send(Request::ReceiveApplication(max_len, tx));
        }) {
            resp
        } else {
            None
        }
    }

    fn can_send_initial(&mut self) -> bool {
        let mut cx = core::task::Context::from_waker(&self.waker);
        if let Poll::Ready(resp) = self.can_send_initial.poll_request(&mut cx, |tx| {
            let _ = self.tx.unbounded_send(Request::CanSendInitial(tx));
        }) {
            resp
        } else {
            // FIXME: either async-ify, remove, or figure out what the Pending value should be.
            false
        }
    }

    fn send_initial(&mut self, transmission: bytes::Bytes) {
        let _ = self.tx.unbounded_send(Request::SendInitial(transmission));
    }

    fn can_send_handshake(&mut self) -> bool {
        let mut cx = core::task::Context::from_waker(&self.waker);
        if let Poll::Ready(resp) = self.can_send_handshake.poll_request(&mut cx, |tx| {
            let _ = self.tx.unbounded_send(Request::CanSendHandshake(tx));
        }) {
            resp
        } else {
            // FIXME: either async-ify, remove, or figure out what the Pending value should be.
            false
        }
    }

    fn send_handshake(&mut self, transmission: bytes::Bytes) {
        let _ = self.tx.unbounded_send(Request::SendHandshake(transmission));
    }

    fn can_send_application(&mut self) -> bool {
        let mut cx = core::task::Context::from_waker(&self.waker);
        if let Poll::Ready(resp) = self.can_send_application.poll_request(&mut cx, |tx| {
            let _ = self.tx.unbounded_send(Request::CanSendApplication(tx));
        }) {
            resp
        } else {
            // FIXME: either async-ify, remove, or figure out what the Pending value should be.
            false
        }
    }

    fn send_application(&mut self, transmission: bytes::Bytes) {
        let _ = self
            .tx
            .unbounded_send(Request::SendApplication(transmission));
    }

    fn waker(&self) -> &core::task::Waker {
        &self.waker
    }
}

struct AsyncRequest<T> {
    rx: Option<Receiver<T>>,
}

impl<T> AsyncRequest<T> {
    fn empty() -> Self {
        AsyncRequest { rx: None }
    }

    fn poll_request(
        &mut self,
        mut cx: &mut core::task::Context<'_>,
        issue: impl FnOnce(Sender<T>),
    ) -> Poll<T> {
        loop {
            if let Some(mut ch) = self.rx.as_mut() {
                match Pin::new(&mut ch).poll(&mut cx) {
                    Poll::Ready(Ok(value)) => {
                        ch.close();
                        self.rx = None;
                        return Poll::Ready(value);
                    }
                    Poll::Ready(Err(_)) => {
                        // treat cancellation as reason to ask again.
                        // FIXME: this probably means that the parent thread is no longer interested
                        // in this connection and we should instead tear it down.
                        ch.close();
                        self.rx = None;
                        // loop around to next loop iteration
                    }
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                let (tx, rx) = futures_channel::oneshot::channel();
                self.rx = Some(rx);
                issue(tx);
                return Poll::Pending;
            }
        }
    }
}

impl<E: Endpoint> Endpoint for OffloadEndpoint<E> {
    type Session = OffloadSession<E::Session>;

    fn new_server_session<Params: s2n_codec::EncoderValue>(
        &mut self,
        transport_parameters: &Params,
    ) -> Self::Session {
        OffloadSession::new(
            self.inner.new_server_session(transport_parameters),
            &mut self.new_stream,
            self.remote_thread.clone(),
        )
    }

    fn new_client_session<Params: s2n_codec::EncoderValue>(
        &mut self,
        transport_parameters: &Params,
        server_name: crate::application::ServerName,
    ) -> Self::Session {
        OffloadSession::new(
            self.inner
                .new_client_session(transport_parameters, server_name),
            &mut self.new_stream,
            self.remote_thread.clone(),
        )
    }

    fn max_tag_length(&self) -> usize {
        self.inner.max_tag_length()
    }
}

enum Request<S: CryptoSuite> {
    HandshakeKeys(
        <S as CryptoSuite>::HandshakeKey,
        <S as CryptoSuite>::HandshakeHeaderKey,
    ),
    ZeroRttKeys(
        <S as CryptoSuite>::ZeroRttKey,
        <S as CryptoSuite>::ZeroRttHeaderKey,
        Vec<u8>,
    ),
    OneRttKeys(
        <S as CryptoSuite>::OneRttKey,
        <S as CryptoSuite>::OneRttHeaderKey,
        Vec<u8>,
    ),
    ServerName(crate::application::ServerName),
    ApplicationProtocol(bytes::Bytes),
    HandshakeComplete,

    Done(S, Result<(), crate::transport::Error>),
    ReceiveInitial(Option<usize>, Sender<Option<bytes::Bytes>>),
    ReceiveApplication(Option<usize>, Sender<Option<bytes::Bytes>>),
    ReceiveHandshake(Option<usize>, Sender<Option<bytes::Bytes>>),
    CanSendInitial(Sender<bool>),
    CanSendHandshake(Sender<bool>),
    CanSendApplication(Sender<bool>),
    SendApplication(bytes::Bytes),
    SendHandshake(bytes::Bytes),
    SendInitial(bytes::Bytes),
    ClientAppParams(Vec<u8>, Vec<u8>),
}

#[derive(Debug)]
pub struct OffloadSession<S: CryptoSuite> {
    // starts out Some, is sent to the background thread, then returns via a Request.
    inner: Option<S>,
    is_poll_done: Option<Result<(), crate::transport::Error>>,
    pending_requests: UnboundedReceiver<Request<S>>,
    remote_thread: Waker,
}

impl<S: CryptoSuite> OffloadSession<S> {
    fn new(
        inner: S,
        new_stream: &mut UnboundedSender<(S, UnboundedSender<Request<S>>)>,
        remote_thread: Waker,
    ) -> Self {
        tracing::trace!("created new offload session");
        let (tx, rx) = futures_channel::mpsc::unbounded::<Request<S>>();
        new_stream.unbounded_send((inner, tx)).unwrap();
        Self {
            inner: None,
            is_poll_done: None,
            pending_requests: rx,
            remote_thread,
        }
    }
}

impl<S> Session for OffloadSession<S>
where
    S: Session,
{
    fn poll<C: Context<Self>>(
        &mut self,
        context: &mut C,
    ) -> core::task::Poll<Result<(), crate::transport::Error>> {
        if let Some(finished) = self.is_poll_done.clone() {
            return core::task::Poll::Ready(finished);
        }

        loop {
            self.remote_thread.wake_by_ref();

            let mut cx = std::task::Context::from_waker(context.waker());
            tracing::trace!("polling remote session for pending requests");
            let req = match Pin::new(&mut self.pending_requests).poll_next(&mut cx) {
                core::task::Poll::Ready(Some(message)) => message,
                core::task::Poll::Ready(None) => {
                    return Poll::Ready(Err(crate::transport::Error::INTERNAL_ERROR
                        .with_reason("offloaded crypto session finished without sending Done")))
                }
                core::task::Poll::Pending => return core::task::Poll::Pending,
            };

            match req {
                Request::Done(session, res) => {
                    tracing::trace!("remote session sent Done");
                    self.inner = Some(session);
                    self.is_poll_done = Some(res.clone());
                    return core::task::Poll::Ready(res);
                }
                Request::HandshakeKeys(key, header_key) => {
                    tracing::trace!("remote session sent HandshakeKeys");
                    context.on_handshake_keys(key, header_key).unwrap();
                }
                Request::ZeroRttKeys(key, header_key, transport_parameters) => {
                    tracing::trace!("remote session sent ZeroRttKeys");
                    context
                        .on_zero_rtt_keys(
                            key,
                            header_key,
                            super::ApplicationParameters {
                                transport_parameters: &transport_parameters,
                            },
                        )
                        .unwrap();
                }
                Request::OneRttKeys(key, header_key, transport_parameters) => {
                    tracing::trace!("remote session sent OneRttKeys");
                    context
                        .on_one_rtt_keys(
                            key,
                            header_key,
                            super::ApplicationParameters {
                                transport_parameters: &transport_parameters,
                            },
                        )
                        .unwrap();
                }
                Request::ServerName(server_name) => {
                    tracing::trace!("remote session sent ServerName");
                    context.on_server_name(server_name).unwrap();
                }
                Request::ApplicationProtocol(application_protocol) => {
                    tracing::trace!("remote session sent ApplicationProtocol");
                    context
                        .on_application_protocol(application_protocol)
                        .unwrap();
                }
                Request::HandshakeComplete => {
                    tracing::trace!("remote session sent HandshakeComplete");
                    context.on_handshake_complete().unwrap();
                }
                Request::ReceiveInitial(max_len, sender) => {
                    let resp = context.receive_initial(max_len);
                    tracing::trace!(
                        "remote session sent ReceiveInitial(max_len={:?}), resp: {:?}",
                        max_len,
                        resp
                    );
                    let _ = sender.send(resp);
                }
                Request::ReceiveHandshake(max_len, sender) => {
                    tracing::trace!("remote session sent ReceiveHandshake");
                    let _ = sender.send(context.receive_handshake(max_len));
                }
                Request::ReceiveApplication(max_len, sender) => {
                    tracing::trace!("remote session sent ReceiveApplication");
                    let _ = sender.send(context.receive_application(max_len));
                }
                Request::CanSendInitial(sender) => {
                    tracing::trace!("remote session sent CanSendInitial");
                    let _ = sender.send(context.can_send_initial());
                }
                Request::CanSendHandshake(sender) => {
                    tracing::trace!("remote session sent CanSendHandshake");
                    let _ = sender.send(context.can_send_handshake());
                }
                Request::CanSendApplication(sender) => {
                    tracing::trace!("remote session sent CanSendApplication");
                    let _ = sender.send(context.can_send_application());
                }
                Request::SendApplication(bytes) => {
                    tracing::trace!("remote session sent SendApplication");
                    context.send_application(bytes);
                }
                Request::SendHandshake(bytes) => {
                    tracing::trace!("remote session sent SendHandshake");
                    context.send_handshake(bytes);
                }
                Request::SendInitial(bytes) => {
                    tracing::trace!("remote session sent SendInitial");
                    context.send_initial(bytes);
                }
                Request::ClientAppParams(client, server) => {
                    let mut server_copy = server.clone();
                    context
                        .on_client_application_params(
                            super::ApplicationParameters {
                                transport_parameters: &client,
                            },
                            &mut server_copy,
                        )
                        .unwrap();
                    if server_copy != server {
                        unimplemented!("modifying parameters not supported (yet) with offload")
                    }
                }
            }
        }
    }

    fn process_post_handshake_message<C: super::Context<Self>>(
        &mut self,
        context: &mut C,
    ) -> Result<(), crate::transport::Error> {
        let Some(inner) = self.inner.as_mut() else {
            unimplemented!("calling process_post_handshake_message before handshake is done");
        };
        inner.process_post_handshake_message(&mut LocalContext {
            context,
            _phantom: PhantomData,
        })
    }

    fn should_discard_session(&self) -> bool {
        // if no session available yet (still in background) we shouldn't discard it.
        self.inner
            .as_ref()
            .map(|v| v.should_discard_session())
            .unwrap_or(false)
    }

    fn parse_hello(
        msg_type: super::HandshakeType,
        header_chunk: &[u8],
        total_received_len: u64,
        max_hello_size: u64,
    ) -> Result<Option<super::HelloOffsets>, crate::transport::Error> {
        S::parse_hello(msg_type, header_chunk, total_received_len, max_hello_size)
    }
}

/// LocalContext is used on the main s2n-quic thread and doesn't perform any special actions, just
/// forwards to the underlying context.
///
/// It is necessary because the bounds on Session require `Context<Self>`, not
/// `Context<$arbitrary>`.
struct LocalContext<'a, C, S> {
    context: &'a mut C,
    _phantom: PhantomData<fn(S)>,
}

impl<C, S1, S2, K1, K2, K3, K4, K5, K6, K7, K8, K9> Context<S1> for LocalContext<'_, C, S2>
where
    C: Context<S2>,
    S1: CryptoSuite<
        HandshakeKey = K1,
        HandshakeHeaderKey = K2,
        InitialKey = K3,
        InitialHeaderKey = K4,
        OneRttKey = K5,
        OneRttHeaderKey = K6,
        ZeroRttKey = K7,
        ZeroRttHeaderKey = K8,
        RetryKey = K9,
    >,
    S2: CryptoSuite<
        HandshakeKey = K1,
        HandshakeHeaderKey = K2,
        InitialKey = K3,
        InitialHeaderKey = K4,
        OneRttKey = K5,
        OneRttHeaderKey = K6,
        ZeroRttKey = K7,
        ZeroRttHeaderKey = K8,
        RetryKey = K9,
    >,
{
    fn on_client_application_params(
        &mut self,
        client_params: super::ApplicationParameters,
        server_params: &mut alloc::vec::Vec<u8>,
    ) -> Result<(), crate::transport::Error> {
        self.context
            .on_client_application_params(client_params, server_params)
    }

    fn on_handshake_keys(
        &mut self,
        key: <S1 as CryptoSuite>::HandshakeKey,
        header_key: <S1 as CryptoSuite>::HandshakeHeaderKey,
    ) -> Result<(), crate::transport::Error> {
        self.context.on_handshake_keys(key, header_key)
    }

    fn on_zero_rtt_keys(
        &mut self,
        key: <S1 as CryptoSuite>::ZeroRttKey,
        header_key: <S1 as CryptoSuite>::ZeroRttHeaderKey,
        application_parameters: super::ApplicationParameters,
    ) -> Result<(), crate::transport::Error> {
        self.context
            .on_zero_rtt_keys(key, header_key, application_parameters)
    }

    fn on_one_rtt_keys(
        &mut self,
        key: <S1 as CryptoSuite>::OneRttKey,
        header_key: <S1 as CryptoSuite>::OneRttHeaderKey,
        application_parameters: super::ApplicationParameters,
    ) -> Result<(), crate::transport::Error> {
        self.context
            .on_one_rtt_keys(key, header_key, application_parameters)
    }

    fn on_server_name(
        &mut self,
        server_name: crate::application::ServerName,
    ) -> Result<(), crate::transport::Error> {
        self.context.on_server_name(server_name)
    }

    fn on_application_protocol(
        &mut self,
        application_protocol: bytes::Bytes,
    ) -> Result<(), crate::transport::Error> {
        self.context.on_application_protocol(application_protocol)
    }

    fn on_handshake_complete(&mut self) -> Result<(), crate::transport::Error> {
        self.context.on_handshake_complete()
    }

    fn on_tls_exporter_ready(
        &mut self,
        session: &impl super::TlsSession,
    ) -> Result<(), crate::transport::Error> {
        self.context.on_tls_exporter_ready(session)
    }

    fn receive_initial(&mut self, max_len: Option<usize>) -> Option<bytes::Bytes> {
        self.context.receive_initial(max_len)
    }

    fn receive_handshake(&mut self, max_len: Option<usize>) -> Option<bytes::Bytes> {
        self.context.receive_handshake(max_len)
    }

    fn receive_application(&mut self, max_len: Option<usize>) -> Option<bytes::Bytes> {
        self.context.receive_application(max_len)
    }

    fn can_send_initial(&mut self) -> bool {
        self.context.can_send_initial()
    }

    fn send_initial(&mut self, transmission: bytes::Bytes) {
        self.context.send_initial(transmission)
    }

    fn can_send_handshake(&mut self) -> bool {
        self.context.can_send_handshake()
    }

    fn send_handshake(&mut self, transmission: bytes::Bytes) {
        self.context.send_handshake(transmission)
    }

    fn can_send_application(&mut self) -> bool {
        self.context.can_send_application()
    }

    fn send_application(&mut self, transmission: bytes::Bytes) {
        self.context.send_application(transmission)
    }

    fn waker(&self) -> &core::task::Waker {
        self.context.waker()
    }
}

impl<S: CryptoSuite> CryptoSuite for OffloadSession<S> {
    type HandshakeKey = S::HandshakeKey;
    type HandshakeHeaderKey = S::HandshakeHeaderKey;
    type InitialKey = S::InitialKey;
    type InitialHeaderKey = S::InitialHeaderKey;
    type OneRttKey = S::OneRttKey;
    type OneRttHeaderKey = S::OneRttHeaderKey;
    type ZeroRttKey = S::ZeroRttKey;
    type ZeroRttHeaderKey = S::ZeroRttHeaderKey;
    type RetryKey = S::RetryKey;
}
