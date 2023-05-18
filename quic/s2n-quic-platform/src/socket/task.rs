// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    features::Gso,
    message::Message,
    socket::ring::{Consumer, Producer},
};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use futures::ready;

pub mod blocking;
pub mod events;

pub trait Tx<T: Message> {
    type Error;

    fn send(
        &mut self,
        cx: &mut Context,
        entries: &mut [T],
        events: &mut events::TxEvents,
    ) -> Result<(), Self::Error>;
}

pub trait Rx<T: Message> {
    type Error;

    fn recv(
        &mut self,
        cx: &mut Context,
        entries: &mut [T],
        events: &mut events::RxEvents,
    ) -> Result<(), Self::Error>;
}

pub struct Sender<T: Message, S: Tx<T>> {
    ring: Consumer<T>,
    tx: S,
    pending: u32,
    events: events::TxEvents,
}

impl<T, S> Sender<T, S>
where
    T: Message + Unpin,
    S: Tx<T> + Unpin,
{
    #[inline]
    pub fn new(ring: Consumer<T>, tx: S, gso: Gso) -> Self {
        Self {
            ring,
            tx,
            pending: 0,
            events: events::TxEvents::new(gso),
        }
    }

    #[inline]
    fn poll_ring(&mut self, watermark: u32, cx: &mut Context) -> Poll<Option<usize>> {
        loop {
            let count = ready!(self.ring.poll_acquire(watermark, cx));

            if count > self.pending {
                return Some(self.pending as usize).into();
            }

            self.release();
        }
    }

    #[inline]
    fn release(&mut self) {
        self.ring.release(self.pending);
        self.pending = 0;
    }
}

impl<T, S> Future for Sender<T, S>
where
    T: Message + Unpin,
    S: Tx<T> + Unpin,
{
    type Output = Option<S::Error>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        while !this.events.take_blocked() {
            let pending = match ready!(this.poll_ring(u32::MAX, cx)) {
                Some(entries) => entries,
                None => return None.into(),
            };

            let entries = &mut this.ring.data()[pending..];

            match this.tx.send(cx, entries, &mut this.events) {
                Ok(()) => this.pending += this.events.take_count() as u32,
                Err(err) => return Some(err).into(),
            }
        }

        this.release();

        Poll::Pending
    }
}

pub struct Receiver<T: Message, S: Rx<T>> {
    ring: Producer<T>,
    rx: S,
    pending: u32,
}

impl<T, S> Receiver<T, S>
where
    T: Message + Unpin,
    S: Rx<T> + Unpin,
{
    #[inline]
    pub fn new(ring: Producer<T>, rx: S) -> Self {
        Self {
            ring,
            rx,
            pending: 0,
        }
    }

    #[inline]
    fn poll_ring(&mut self, watermark: u32, cx: &mut Context) -> Poll<Option<usize>> {
        loop {
            let count = ready!(self.ring.poll_acquire(watermark, cx));

            if count > self.pending {
                return Some(self.pending as usize).into();
            }

            self.release();
        }
    }

    #[inline]
    fn release(&mut self) {
        self.ring.release(self.pending);
        self.pending = 0;
    }
}

impl<T, S> Future for Receiver<T, S>
where
    T: Message + Unpin,
    S: Rx<T> + Unpin,
{
    type Output = Option<S::Error>;

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut events = events::RxEvents::default();

        while !events.take_blocked() {
            let pending = match ready!(this.poll_ring(u32::MAX, cx)) {
                Some(entries) => entries,
                None => return None.into(),
            };

            let entries = &mut this.ring.data()[pending..];

            match this.rx.recv(cx, entries, &mut events) {
                Ok(()) => this.pending += events.take_count() as u32,
                Err(err) => return Some(err).into(),
            }
        }

        this.release();

        Poll::Pending
    }
}
