// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::features::Gso;
use core::ops::ControlFlow;

#[derive(Debug)]
pub struct TxEvents {
    count: usize,
    is_blocked: bool,
    is_interrupted: bool,
    #[cfg_attr(s2n_quic_platform_gso, allow(dead_code))]
    gso: Gso,
}

impl TxEvents {
    #[inline]
    pub fn new(gso: Gso) -> Self {
        Self {
            count: 0,
            is_blocked: false,
            is_interrupted: false,
            gso,
        }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        self.is_blocked
    }

    #[inline]
    pub fn is_interrupted(&self) -> bool {
        self.is_interrupted
    }

    #[inline]
    pub fn take_blocked(&mut self) -> bool {
        core::mem::take(&mut self.is_blocked)
    }

    #[inline]
    pub fn take_interrupted(&mut self) -> bool {
        core::mem::take(&mut self.is_interrupted)
    }

    #[inline]
    pub fn blocked(&mut self) {
        self.is_blocked = true;
    }

    #[inline]
    pub fn take_count(&mut self) -> usize {
        core::mem::take(&mut self.count)
    }
}

impl crate::syscall::SocketEvents for TxEvents {
    #[inline]
    fn on_complete(&mut self, count: usize) -> ControlFlow<(), ()> {
        self.count += count;
        self.is_blocked = false;
        self.is_interrupted = false;
        ControlFlow::Continue(())
    }

    #[inline]
    fn on_error(&mut self, error: ::std::io::Error) -> ControlFlow<(), ()> {
        // TODO log this
        use std::io::ErrorKind::*;

        match error.kind() {
            WouldBlock => {
                self.is_blocked = true;
                ControlFlow::Break(())
            }
            Interrupted => {
                self.is_interrupted = true;
                ControlFlow::Break(())
            }
            #[cfg(s2n_quic_platform_gso)]
            _ if errno::errno().0 == libc::EIO => {
                self.count += 1;

                self.gso.disable();

                ControlFlow::Continue(())
            }
            #[cfg(unix)]
            _ if errno::errno().0 == libc::EMSGSIZE => {
                self.count += 1;
                ControlFlow::Continue(())
            }
            _ => {
                self.count += 1;
                dbg!(&error);
                ControlFlow::Continue(())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct RxEvents {
    count: usize,
    is_blocked: bool,
    is_interrupted: bool,
}

impl RxEvents {
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        self.is_blocked
    }

    #[inline]
    pub fn is_interrupted(&self) -> bool {
        self.is_interrupted
    }

    #[inline]
    pub fn take_blocked(&mut self) -> bool {
        core::mem::take(&mut self.is_blocked)
    }

    #[inline]
    pub fn take_interrupted(&mut self) -> bool {
        core::mem::take(&mut self.is_interrupted)
    }

    #[inline]
    pub fn blocked(&mut self) {
        self.is_blocked = true;
    }

    #[inline]
    pub fn take_count(&mut self) -> usize {
        core::mem::take(&mut self.count)
    }
}

impl crate::syscall::SocketEvents for RxEvents {
    #[inline]
    fn on_complete(&mut self, count: usize) -> ControlFlow<(), ()> {
        self.count += count;
        self.is_blocked = false;
        self.is_interrupted = false;
        ControlFlow::Continue(())
    }

    #[inline]
    fn on_error(&mut self, error: ::std::io::Error) -> ControlFlow<(), ()> {
        // TODO log this
        use std::io::ErrorKind::*;

        match error.kind() {
            WouldBlock => {
                self.is_blocked = true;
                ControlFlow::Break(())
            }
            Interrupted => {
                self.is_interrupted = true;
                ControlFlow::Break(())
            }
            _ => {
                self.count += 1;
                dbg!(&error);
                ControlFlow::Break(())
            }
        }
    }
}
