// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::state::State;
use crate::{
    event::{self, EndpointPublisher as _},
    path::secret::map::store::Store,
};
use rand::{seq::SliceRandom, Rng as _};
use s2n_quic_core::time;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

const EVICTION_CYCLES: u64 = if cfg!(test) { 0 } else { 10 };

pub struct Cleaner {
    should_stop: AtomicBool,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    epoch: AtomicU64,
}

impl Drop for Cleaner {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Cleaner {
    pub fn new() -> Cleaner {
        Cleaner {
            should_stop: AtomicBool::new(false),
            thread: Mutex::new(None),
            epoch: AtomicU64::new(1),
        }
    }

    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::Relaxed);
        if let Some(thread) =
            std::mem::take(&mut *self.thread.lock().unwrap_or_else(|e| e.into_inner()))
        {
            thread.thread().unpark();

            // If this isn't getting dropped on the cleaner thread,
            // then wait for the background thread to finish exiting.
            if std::thread::current().id() != thread.thread().id() {
                // We expect this to terminate very quickly.
                thread.join().unwrap();
            }
        }
    }

    pub fn spawn_thread<C, S>(&self, state: Arc<State<C, S>>)
    where
        C: 'static + time::Clock + Send + Sync,
        S: event::Subscriber,
    {
        let state = Arc::downgrade(&state);
        let handle = std::thread::Builder::new()
            .name("dc_quic::cleaner".into())
            .spawn(move || loop {
                // in tests, we should try and be as deterministic as possible
                let pause = if cfg!(test) {
                    60
                } else {
                    rand::rng().random_range(5..60)
                };

                let next_start = Instant::now() + Duration::from_secs(pause);
                std::thread::park_timeout(Duration::from_secs(pause));

                let Some(state) = state.upgrade() else {
                    break;
                };
                if state.cleaner().should_stop.load(Ordering::Relaxed) {
                    break;
                }
                state.cleaner().clean(&state, EVICTION_CYCLES);

                // pause the rest of the time to run once a minute, not twice a minute
                std::thread::park_timeout(next_start.saturating_duration_since(Instant::now()));
            })
            .unwrap();
        *self.thread.lock().unwrap() = Some(handle);
    }

    /// Periodic maintenance for various maps.
    pub fn clean<C, S>(&self, state: &State<C, S>, eviction_cycles: u64)
    where
        C: 'static + time::Clock + Send + Sync,
        S: event::Subscriber,
    {
        let current_epoch = self.epoch.fetch_add(1, Ordering::Relaxed);

        let utilization = |count: usize| (count as f32 / state.secrets_capacity() as f32) * 100.0;

        let id_entries_initial = state.ids.len();
        let mut id_entries_retired = 0usize;
        let mut id_entries_active = 0usize;
        let address_entries_initial = state.peers.len();
        let mut address_entries_retired = 0usize;
        let mut address_entries_active = 0usize;

        // We want to avoid taking long lived locks which affect gets on the maps (where we want
        // p100 latency to be in microseconds at most).
        //
        // Impeding *handshake* latency is much more acceptable though since this happens at most
        // once a minute and handshakes are of similar magnitude (~milliseconds/handshake, this is
        // also expected to run for single digit milliseconds).
        //
        // Note that we expect the queue to be an exhaustive list of entries - no entry should not
        // be in the queue but be in the maps for more than a few microseconds during a handshake
        // (when we pop from the queue to remove from the maps).
        let mut queue = state
            .eviction_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // This map is only accessed with queue lock held and in cleaner, so it is in practice
        // single threaded. No concurrent access is permitted.
        state.cleaner_peer_seen.clear();

        let mut rehandshake_queue = state.cleaner_handshake_queue.lock().unwrap();
        let refill_rehandshakes = rehandshake_queue.is_empty();

        // FIXME: add metrics for queue depth?
        // These are sort of equivalent to the ID map -- so maybe not worth it for now unless we
        // can get something more interesting out of it.
        queue.retain(|entry| {
            let Some(entry) = entry.upgrade() else {
                return false;
            };

            if entry.take_accessed_id() {
                id_entries_active += 1;
            }

            // Avoid double counting by making sure we have unique peer IPs.
            // We clear/take the accessed bit regardless of whether we're going to count it to
            // preserve the property that every cleaner run snapshots last ~minute.
            if entry.take_accessed_addr() && state.cleaner_peer_seen.insert(entry.clone()).is_none()
            {
                address_entries_active += 1;
            }

            let retained = if let Some(retired_at) = entry.retired_at() {
                // retain if we aren't yet ready to evict.
                current_epoch.saturating_sub(retired_at) < eviction_cycles
            } else {
                // always retain non-retired entries.
                true
            };

            if !retained {
                let (id_removed, peer_removed) = state.evict(&entry);
                if id_removed {
                    id_entries_retired += 1;
                }
                if peer_removed {
                    address_entries_retired += 1;
                }
                return false;
            }

            if refill_rehandshakes {
                // We'll dedup after we fill, we preallocate for the max capacity so this shouldn't
                // allocate in practice.
                rehandshake_queue.push(*entry.peer());
            }

            true
        });

        // Avoid retaining entries for longer than expected.
        state.cleaner_peer_seen.clear();

        drop(queue);

        if refill_rehandshakes {
            rehandshake_queue.sort_unstable();
            rehandshake_queue.dedup();

            // Shuffling each time we pull a new queue means that we have p100 re-handshake time
            // double the expected handshake period, because the entry handshaked at p0 on the
            // first pass might end up at p100 on the second pass. We're OK with that tradeoff --
            // the randomization avoids thundering herds against the same host, and while we could
            // remember an order it's harder to get diffing that order with new entries right.
            let mut rng = rand::rng();
            rehandshake_queue.shuffle(&mut rng);
        }

        // Get the number of handshakes we should run during each minute.
        let mut to_select = (60.0 * state.peers.len() as f64
            / state.rehandshake_period().as_secs() as f64)
            .trunc() as usize;
        let mut handshake_at = state.cleaner_handshake_at.lock().unwrap();

        // Roll a random number *once* to schedule the tail handshake. This avoids repeatedly
        // rolling false if we rolled every minute with a small probability of success. This mostly
        // matters in cases where to_select is otherwise zero (i.e., with small peer counts).
        let max_delay = (60.0 * state.rehandshake_period().as_secs() as f64
            / state.peers.len() as f64)
            .ceil() as u64;
        if handshake_at.is_none() && max_delay > 0 {
            *handshake_at = Some(
                std::time::Instant::now() + Duration::from_secs(rand::random_range(0..max_delay)),
            );
        }
        // If the time when we should add the single handshake, then add it.
        if handshake_at.is_some_and(|t| t <= Instant::now()) {
            to_select += 1;
            *handshake_at = None;
        }

        let mut handshake_requests = 0;
        // request handshakes in smaller batches to avoid overloading the peer.
        // this is expected to still run in way under a minute.
        'outer: for chunk in rehandshake_queue.rchunks(25) {
            for entry in chunk {
                if let Some(n) = to_select.checked_sub(1) {
                    to_select = n;
                } else {
                    break 'outer;
                }

                handshake_requests += 1;

                state.request_handshake(*entry);
            }
            // Consider spreading more evenly across the full minute?
            // Since we handshake in bursts of 25, this still allows 60*1000/50*25 = 30k
            // handshakes/minute, which is orders of magnitude more than we should ever have. At
            // 500k peers with a 24 hour handshake period means ~348 handshakes/minute.
            std::thread::sleep(Duration::from_millis(50));
        }

        let new_len = rehandshake_queue.len() - handshake_requests;
        rehandshake_queue.truncate(new_len);
        drop(rehandshake_queue);

        let id_entries = state.ids.len();
        let address_entries = state.peers.len();

        state.subscriber().on_path_secret_map_cleaner_cycled(
            event::builder::PathSecretMapCleanerCycled {
                id_entries,
                id_entries_retired,
                id_entries_active,
                id_entries_active_utilization: utilization(id_entries_active),
                id_entries_utilization: utilization(id_entries),
                id_entries_initial_utilization: utilization(id_entries_initial),
                address_entries,
                address_entries_active,
                address_entries_active_utilization: utilization(address_entries_active),
                address_entries_utilization: utilization(address_entries),
                address_entries_initial_utilization: utilization(address_entries_initial),
                address_entries_retired,
                handshake_requests,
                handshake_requests_retired: 0,
            },
        );
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }
}
