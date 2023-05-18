// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::message::Message;
use alloc::sync::Arc;
use core::{
    mem::size_of,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::AtomicU32,
    task::{Context, Poll},
};
use s2n_quic_core::sync::{
    atomic_waker,
    cursor::{self, Cursor},
    CachePadded,
};

const CURSOR_SIZE: usize = size_of::<CachePadded<AtomicU32>>();
const PRODUCER_OFFSET: usize = 0;
const CONSUMER_OFFSET: usize = CURSOR_SIZE;
const DATA_OFFSET: usize = CURSOR_SIZE * 2;

pub fn pair<T: Message>(entries: u32, payload_len: u32) -> (Producer<T>, Consumer<T>) {
    let mut storage = T::alloc(entries, payload_len, DATA_OFFSET);

    let ptr = NonNull::new(storage.as_mut_ptr()).unwrap();
    let storage = Arc::new(storage);

    let wakers = atomic_waker::pair();

    let consumer = Consumer {
        cursor: unsafe { builder(ptr, entries).build_consumer() },
        wakers: wakers.0,
        storage: storage.clone(),
    };

    let producer = Producer {
        cursor: unsafe { builder(ptr, entries).build_producer() },
        wakers: wakers.1,
        storage,
    };

    (producer, consumer)
}

pub struct Consumer<T: Message> {
    cursor: Cursor<T>,
    wakers: atomic_waker::Handle,
    #[allow(dead_code)]
    storage: Arc<Pin<Box<[u8]>>>,
}

unsafe impl<T: Message> Send for Consumer<T> {}
unsafe impl<T: Message> Sync for Consumer<T> {}

impl<T: Message> Consumer<T> {
    #[inline]
    pub fn acquire(&mut self, watermark: u32) -> u32 {
        self.cursor.acquire_consumer(watermark)
    }

    #[inline]
    pub async fn acquire_async(&mut self, watermark: u32) -> u32 {
        futures::future::poll_fn(|cx| self.poll_acquire(watermark, cx)).await
    }

    #[inline]
    pub fn poll_acquire(&mut self, watermark: u32, cx: &mut Context) -> Poll<u32> {
        macro_rules! try_acquire {
            () => {{
                let count = self.acquire(watermark);

                if count > 0 {
                    return Poll::Ready(count);
                }
            }};
        }

        try_acquire!();

        self.wakers.register(cx.waker());

        try_acquire!();

        Poll::Pending
    }

    #[inline]
    pub fn release(&mut self, len: u32) {
        self.cursor.release_consumer(len);

        self.wakers.wake();
    }

    #[inline]
    pub fn data(&mut self) -> &mut [T] {
        let idx = self.cursor.cached_consumer();
        let len = self.cursor.cached_consumer_len();
        let ptr = self.cursor.data_ptr();
        #[allow(dead_code)]
        unsafe {
            let ptr = ptr.as_ptr().add(idx as _);
            core::slice::from_raw_parts_mut(ptr, len as _)
        }
    }

    #[inline]
    pub fn is_open(&self) -> bool {
        self.wakers.is_open()
    }
}

pub struct Producer<T: Message> {
    cursor: Cursor<T>,
    wakers: atomic_waker::Handle,
    #[allow(dead_code)]
    storage: Arc<Pin<Box<[u8]>>>,
}

unsafe impl<T: Message> Send for Producer<T> {}
unsafe impl<T: Message> Sync for Producer<T> {}

impl<T: Message> Producer<T> {
    #[inline]
    pub fn acquire(&mut self, watermark: u32) -> u32 {
        self.cursor.acquire_producer(watermark)
    }

    #[inline]
    pub async fn acquire_async(&mut self, watermark: u32) -> u32 {
        futures::future::poll_fn(|cx| self.poll_acquire(watermark, cx)).await
    }

    #[inline]
    pub fn poll_acquire(&mut self, watermark: u32, cx: &mut Context) -> Poll<u32> {
        macro_rules! try_acquire {
            () => {{
                let count = self.acquire(watermark);

                if count > 0 {
                    return Poll::Ready(count);
                }
            }};
        }

        try_acquire!();

        self.wakers.register(cx.waker());

        try_acquire!();

        Poll::Pending
    }

    #[inline]
    pub fn release(&mut self, len: u32) {
        if len == 0 {
            return;
        }

        debug_assert!(len <= self.cursor.cached_producer_len());

        let idx = self.cursor.cached_producer();
        let size = self.cursor.capacity();

        unsafe {
            let replication_count = (size - idx).min(len);

            debug_assert_ne!(replication_count, 0);

            let ptr = self.cursor.data_ptr().as_ptr().add(idx as _);

            let primary = ptr;
            let secondary = ptr.add(size as _);

            self.replicate(primary, secondary, replication_count as _);
        }

        if let Some(replication_count) = (idx + len).checked_sub(size).filter(|v| *v > 0) {
            unsafe {
                let ptr = self.cursor.data_ptr().as_ptr();

                let primary = ptr;
                let secondary = ptr.add(size as _);

                self.replicate(secondary, primary, replication_count as _);
            }
        }

        self.cursor.release_producer(len);

        self.wakers.wake();
    }

    #[inline]
    pub fn data(&mut self) -> &mut [T] {
        let idx = self.cursor.cached_producer();
        let len = self.cursor.cached_producer_len();
        let ptr = self.cursor.data_ptr();
        unsafe {
            let ptr = ptr.as_ptr().add(idx as _);
            core::slice::from_raw_parts_mut(ptr, len as _)
        }
    }

    #[inline]
    pub fn is_open(&self) -> bool {
        self.wakers.is_open()
    }

    #[inline]
    pub fn capacity(&self) -> u32 {
        self.cursor.capacity()
    }

    #[inline]
    unsafe fn replicate(&self, primary: *mut T, secondary: *mut T, len: usize) {
        debug_assert_ne!(len, 0);

        #[cfg(debug_assertions)]
        {
            let primary = core::slice::from_raw_parts(primary, len as _);
            let secondary = core::slice::from_raw_parts(secondary, len as _);
            for (primary, secondary) in primary.iter().zip(secondary) {
                T::validate_replication(primary, secondary);
            }
        }

        core::ptr::copy_nonoverlapping(primary, secondary, len as _);
    }
}

#[inline]
unsafe fn builder<T: Message>(ptr: NonNull<u8>, size: u32) -> cursor::Builder<T> {
    let ptr = ptr.as_ptr();
    let producer = ptr.add(PRODUCER_OFFSET) as *mut _;
    let producer = NonNull::new(producer).unwrap();
    let consumer = ptr.add(CONSUMER_OFFSET) as *mut _;
    let consumer = NonNull::new(consumer).unwrap();
    let data = ptr.add(DATA_OFFSET) as *mut _;
    let data = NonNull::new(data).unwrap();

    cursor::Builder {
        producer,
        consumer,
        data,
        size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bolero::check;

    #[test]
    fn replication_test() {
        check!().with_type::<Vec<u32>>().for_each(|counts| {
            let entries = 16;

            let (mut producer, mut consumer) =
                pair::<crate::message::simple::Message>(entries, 100);

            let mut counter = 0;

            for count in counts.iter().copied() {
                let count = producer.acquire(count);

                for entry in &mut producer.data()[..count as usize] {
                    unsafe {
                        entry.set_payload_len(counter);
                    }
                    counter += 1;
                }

                producer.release(count);

                for idx in 0..entries {
                    let ptr = producer.cursor.data_ptr().as_ptr();
                    unsafe {
                        let primary = &*ptr.add(idx as _);
                        let secondary = &*ptr.add((idx + entries) as _);

                        assert_eq!(primary.payload_len(), secondary.payload_len());
                    }
                }

                let count = consumer.acquire(count);
                consumer.release(count);
            }
        });
    }
}
