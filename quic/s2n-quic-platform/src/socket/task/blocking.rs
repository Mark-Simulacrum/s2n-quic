// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    features::Gso,
    message::Message,
    socket::{
        ring::{Consumer, Producer},
        task::{
            self,
            events::{RxEvents, TxEvents},
            Rx, Tx,
        },
    },
};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use parking::Unparker;
use s2n_quic_core::time::{self, Timestamp};
use std::{net::UdpSocket, sync::Arc};

struct ThreadWaker(Unparker);

impl std::task::Wake for ThreadWaker {
    #[inline]
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    #[inline]
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

#[derive(Clone, Default)]
pub struct Clock {
    clock: time::StdClock,
    timer: Timer,
}

impl time::Clock for Clock {
    #[inline]
    fn get_time(&self) -> Timestamp {
        self.clock.get_time()
    }
}

impl time::ClockWithTimer for Clock {
    type Timer = Timer;

    #[inline]
    fn timer(&self) -> Self::Timer {
        self.timer.clone()
    }
}

#[derive(Clone)]
pub struct Timer(Arc<AtomicU64>);

impl Default for Timer {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }
}

impl time::clock::Timer for Timer {
    #[inline]
    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<()> {
        if self.0.load(Ordering::Relaxed) == u64::MAX {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    #[inline]
    fn update(&mut self, deadline: Timestamp) {
        let deadline = unsafe { deadline.as_duration().as_micros() as u64 };
        self.0.store(deadline, Ordering::Relaxed)
    }
}

pub fn endpoint<E, F>(setup: E)
where
    E: FnOnce(Clock) -> F,
    F: Future<Output = ()>,
{
    use time::Clock as _;

    let clock = Clock::default();
    let mut future = setup(clock.clone());
    let mut future = unsafe { Pin::new_unchecked(&mut future) };

    let (parker, unparker) = parking::pair();
    let waker = ThreadWaker(unparker);
    let waker = Arc::new(waker).into();
    let mut cx = Context::from_waker(&waker);

    loop {
        match Future::poll(future.as_mut(), &mut cx) {
            Poll::Ready(_) => return,
            Poll::Pending => {
                let target = clock.timer.0.load(Ordering::Relaxed);

                if target == 0 {
                    parker.park();
                    continue;
                }

                let now = unsafe { clock.get_time().as_duration().as_micros() as u64 };
                let diff = target.saturating_sub(now);
                if diff > 1000 {
                    let timeout = core::time::Duration::from_micros(diff);
                    parker.park_timeout(timeout);
                }
                clock.timer.0.store(u64::MAX, Ordering::Relaxed);
            }
        }
    }
}

pub fn tx<S, M>(socket: S, ring: Consumer<M>, gso: Gso) -> Result<(), <UdpSocket as Tx<M>>::Error>
where
    S: Into<UdpSocket>,
    M: Message + Unpin,
    UdpSocket: Tx<M>,
{
    let socket = socket.into();
    socket.set_nonblocking(false).unwrap();

    let task = task::Sender::new(ring, socket, gso);

    if let Some(err) = poll_blocking(task) {
        Err(err)
    } else {
        Ok(())
    }
}

pub fn rx<S, M>(socket: S, ring: Producer<M>) -> Result<(), <UdpSocket as Rx<M>>::Error>
where
    S: Into<UdpSocket>,
    M: Message + Unpin,
    UdpSocket: Rx<M>,
{
    let socket = socket.into();
    socket.set_nonblocking(false).unwrap();

    let task = task::Receiver::new(ring, socket);

    if let Some(err) = poll_blocking(task) {
        Err(err)
    } else {
        Ok(())
    }
}

#[inline]
fn poll_blocking<F: Future>(mut task: F) -> F::Output {
    // TODO use the pin! macro once stable
    let mut task = unsafe { Pin::new_unchecked(&mut task) };

    let (parker, unparker) = parking::pair();
    let waker = ThreadWaker(unparker);
    let waker = Arc::new(waker).into();
    let mut cx = Context::from_waker(&waker);

    let mut stalls = 0;

    loop {
        match task.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {
                stalls += 1;
                if stalls > 10 {
                    stalls = 0;
                    parker.park();
                }
                continue;
            }
        }
    }
}

mod simple {
    use super::*;
    use crate::{
        message::{simple::Message, Message as _},
        syscall::SocketEvents,
    };
    use std::io;

    impl Tx<Message> for UdpSocket {
        type Error = io::Error;

        #[inline]
        fn send(
            &mut self,
            _cx: &mut Context,
            entries: &mut [Message],
            events: &mut TxEvents,
        ) -> io::Result<()> {
            for entry in entries {
                let target = *entry.remote_address();
                let payload = entry.payload_mut();
                match self.send_to(payload, target) {
                    Ok(_) => {
                        if events.on_complete(1).is_break() {
                            return Ok(());
                        }
                    }
                    Err(err) => {
                        if events.on_error(err).is_break() {
                            return Ok(());
                        }
                    }
                }
            }

            Ok(())
        }
    }

    impl Rx<Message> for UdpSocket {
        type Error = io::Error;

        #[inline]
        fn recv(
            &mut self,
            _cx: &mut Context,
            entries: &mut [Message],
            events: &mut RxEvents,
        ) -> io::Result<()> {
            if let Some(entry) = entries.first_mut() {
                let payload = entry.payload_mut();
                match self.recv_from(payload) {
                    Ok((len, addr)) => {
                        unsafe {
                            entry.set_payload_len(len);
                        }
                        entry.set_remote_address(addr.into());

                        if events.on_complete(1).is_break() {
                            return Ok(());
                        }
                    }
                    Err(err) => {
                        if events.on_error(err).is_break() {
                            return Ok(());
                        }
                    }
                }
            }

            Ok(())
        }
    }
}

macro_rules! libc_msg {
    ($message:ident, $cfg:ident) => {
        #[cfg($cfg)]
        mod $message {
            use super::*;
            use crate::{
                message::$message::Message,
                syscall::{$message as syscall, SocketType},
            };
            use std::io;

            impl super::Tx<Message> for UdpSocket {
                type Error = io::Error;

                #[inline]
                fn send(
                    &mut self,
                    _cx: &mut Context,
                    entries: &mut [Message],
                    events: &mut TxEvents,
                ) -> io::Result<()> {
                    syscall::send(self, entries, events);
                    Ok(())
                }
            }

            impl super::Rx<Message> for UdpSocket {
                type Error = io::Error;

                #[inline]
                fn recv(
                    &mut self,
                    _cx: &mut Context,
                    entries: &mut [Message],
                    events: &mut RxEvents,
                ) -> io::Result<()> {
                    syscall::recv(self, SocketType::Blocking, entries, events);
                    Ok(())
                }
            }
        }
    };
}

libc_msg!(msg, s2n_quic_platform_socket_msg);
libc_msg!(mmsg, s2n_quic_platform_socket_mmsg);
