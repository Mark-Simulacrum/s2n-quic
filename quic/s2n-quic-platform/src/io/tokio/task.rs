// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)] // depending on the platform, some of these implementations aren't used

use crate::socket::task::{
    events::{RxEvents, TxEvents},
    Rx, Tx,
};
use core::task::{Context, Poll};

cfg_if::cfg_if! {
    if #[cfg(s2n_quic_platform_socket_mmsg)] {
        pub use mmsg::{rx, tx};
    } else if #[cfg(s2n_quic_platform_socket_msg)] {
        pub use msg::{rx, tx};
    } else {
        pub use simple::{rx, tx};
    }
}

mod simple {
    use super::*;
    use crate::{
        features::Gso,
        message::{simple::Message, Message as _},
        socket::{ring, task},
        syscall::SocketEvents,
    };
    use tokio::{io, net::UdpSocket};

    pub async fn rx<S: Into<std::net::UdpSocket>>(
        socket: S,
        producer: ring::Producer<Message>,
    ) -> io::Result<()> {
        let socket = socket.into();
        socket.set_nonblocking(true).unwrap();

        let socket = UdpSocket::from_std(socket).unwrap();
        let result = task::Receiver::new(producer, socket).await;
        if let Some(err) = result {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub async fn tx<S: Into<std::net::UdpSocket>>(
        socket: S,
        consumer: ring::Consumer<Message>,
        gso: Gso,
    ) -> io::Result<()> {
        let socket = socket.into();
        socket.set_nonblocking(true).unwrap();

        let socket = UdpSocket::from_std(socket).unwrap();
        let result = task::Sender::new(consumer, socket, gso).await;
        if let Some(err) = result {
            Err(err)
        } else {
            Ok(())
        }
    }

    impl Tx<Message> for UdpSocket {
        type Error = io::Error;

        #[inline]
        fn send(
            &mut self,
            cx: &mut Context,
            entries: &mut [Message],
            events: &mut TxEvents,
        ) -> io::Result<()> {
            for entry in entries {
                let target = (*entry.remote_address()).into();
                let payload = entry.payload_mut();
                match self.poll_send_to(cx, payload, target) {
                    Poll::Ready(Ok(_)) => {
                        if events.on_complete(1).is_break() {
                            return Ok(());
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        if events.on_error(err).is_break() {
                            return Ok(());
                        }
                    }
                    Poll::Pending => {
                        events.blocked();
                        break;
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
            cx: &mut Context,
            entries: &mut [Message],
            events: &mut RxEvents,
        ) -> io::Result<()> {
            for entry in entries {
                let payload = entry.payload_mut();
                let mut buf = io::ReadBuf::new(payload);
                match self.poll_recv_from(cx, &mut buf) {
                    Poll::Ready(Ok(addr)) => {
                        unsafe {
                            let len = buf.filled().len();
                            entry.set_payload_len(len);
                        }
                        entry.set_remote_address(addr.into());

                        if events.on_complete(1).is_break() {
                            return Ok(());
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        if events.on_error(err).is_break() {
                            return Ok(());
                        }
                    }
                    Poll::Pending => {
                        events.blocked();
                        break;
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
                features::Gso,
                message::$message::Message,
                socket::{ring, task},
                syscall::{$message as syscall, SocketType},
            };
            use std::{io, os::unix::io::AsRawFd};
            use tokio::io::unix::AsyncFd;

            pub async fn rx<S: Into<std::net::UdpSocket>>(
                socket: S,
                producer: ring::Producer<Message>,
            ) -> io::Result<()> {
                let socket = socket.into();
                socket.set_nonblocking(true).unwrap();

                let socket = AsyncFd::new(socket).unwrap();
                let result = task::Receiver::new(producer, socket).await;
                if let Some(err) = result {
                    Err(err)
                } else {
                    Ok(())
                }
            }

            pub async fn tx<S: Into<std::net::UdpSocket>>(
                socket: S,
                consumer: ring::Consumer<Message>,
                gso: Gso,
            ) -> io::Result<()> {
                let socket = socket.into();
                socket.set_nonblocking(true).unwrap();

                let socket = AsyncFd::new(socket).unwrap();
                let result = task::Sender::new(consumer, socket, gso).await;
                if let Some(err) = result {
                    Err(err)
                } else {
                    Ok(())
                }
            }

            impl<S: AsRawFd> super::Tx<Message> for AsyncFd<S> {
                type Error = io::Error;

                #[inline]
                fn send(
                    &mut self,
                    cx: &mut Context,
                    entries: &mut [Message],
                    events: &mut TxEvents,
                ) -> io::Result<()> {
                    syscall::send(self.get_ref(), entries, events);

                    if !events.is_blocked() {
                        return Ok(());
                    }

                    for i in 0..2 {
                        match self.poll_write_ready(cx) {
                            Poll::Ready(guard) => {
                                let mut guard = guard?;
                                if i == 0 {
                                    guard.clear_ready();
                                } else {
                                    events.take_blocked();
                                }
                            }
                            Poll::Pending => {
                                return Ok(());
                            }
                        }
                    }

                    Ok(())
                }
            }

            impl<S: AsRawFd> super::Rx<Message> for AsyncFd<S> {
                type Error = io::Error;

                #[inline]
                fn recv(
                    &mut self,
                    cx: &mut Context,
                    entries: &mut [Message],
                    events: &mut RxEvents,
                ) -> io::Result<()> {
                    syscall::recv(self.get_ref(), SocketType::NonBlocking, entries, events);

                    if !events.is_blocked() {
                        return Ok(());
                    }

                    for i in 0..2 {
                        match self.poll_read_ready(cx) {
                            Poll::Ready(guard) => {
                                let mut guard = guard?;
                                if i == 0 {
                                    guard.clear_ready();
                                } else {
                                    events.take_blocked();
                                }
                            }
                            Poll::Pending => {
                                return Ok(());
                            }
                        }
                    }

                    Ok(())
                }
            }
        }
    };
}

libc_msg!(msg, s2n_quic_platform_socket_msg);
libc_msg!(mmsg, s2n_quic_platform_socket_mmsg);
