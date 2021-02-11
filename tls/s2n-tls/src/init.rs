use crate::error::Error;
use s2n_tls_sys::*;
use std::sync::Once;

static S2N_INIT: Once = Once::new();

/// # Safety
///
/// This function should only be called once
unsafe fn global_init() -> Result<(), Error> {
    mem::init()?;
    call!(s2n_init())?;
    Ok(())
}

thread_local! {
    static S2N_THREAD: Thread = {
        S2N_INIT.call_once(|| unsafe {
            // Safety: by using `Once` we can ensure the library is initialized once
            global_init().expect("could not initialize s2n-tls");
        });
        Thread
    };
}

struct Thread;

impl Drop for Thread {
    fn drop(&mut self) {
        // https://doc.rust-lang.org/std/thread/struct.LocalKey.html#platform-specific-behavior
        // Note that a "best effort" is made to ensure that destructors for types stored in thread local storage are run, but not all platforms can guarantee that destructors will be run for all types in thread local storage.
        let _ = call!(s2n_cleanup());
    }
}

pub fn init() {
    S2N_THREAD.with(|_| ());
}

mod mem {
    use super::*;
    use alloc::alloc::{alloc, dealloc, Layout};
    use core::{ffi::c_void, mem::size_of};

    pub unsafe fn init() -> Result<(), Error> {
        call!(s2n_mem_set_callbacks(
            Some(mem_init_callback),
            Some(mem_cleanup_callback),
            Some(mem_malloc_callback),
            Some(mem_free_callback),
        ))?;
        Ok(())
    }

    unsafe extern "C" fn mem_init_callback() -> s2n_status_code {
        // no-op: the global allocator is already initialized
        0
    }

    unsafe extern "C" fn mem_cleanup_callback() -> s2n_status_code {
        // no-op: the global allocator is already initialized
        0
    }

    unsafe extern "C" fn mem_malloc_callback(
        ptr: *mut *mut c_void,
        requested_len: u32,
        allocated_len: *mut u32,
    ) -> s2n_status_code {
        let layout = if let Some(layout) = layout(requested_len) {
            layout
        } else {
            return -1;
        };
        *ptr = alloc(layout) as *mut _;

        if ptr.is_null() {
            -1
        } else {
            *allocated_len = requested_len;
            0
        }
    }

    unsafe extern "C" fn mem_free_callback(ptr: *mut c_void, len: u32) -> s2n_status_code {
        let layout = if let Some(layout) = layout(len) {
            layout
        } else {
            return -1;
        };

        dealloc(ptr as *mut _, layout);

        0
    }

    unsafe fn layout(len: u32) -> Option<Layout> {
        // https://linux.die.net/man/3/malloc
        //# The malloc() and calloc() functions return a pointer to the
        //# allocated memory, which is suitably aligned for any built-in
        //# type.
        const ALIGNMENT: usize = size_of::<usize>();

        // * align must not be zero,
        //
        // * align must be a power of two,
        //
        // * size, when rounded up to the nearest multiple of align, must not overflow (i.e., the rounded value must be less than or equal to usize::MAX).

        Layout::from_size_align(len as usize, ALIGNMENT).ok()
    }
}