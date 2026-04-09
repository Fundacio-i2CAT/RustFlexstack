// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! Raw FFI bindings to the `cv2x_wrapper_c` shared library.
//!
//! This module is only compiled when the `cv2x` Cargo feature is enabled.
//! It declares the C functions from `cv2x_wrapper.h` and provides a minimal
//! safe wrapper ([`Cv2xHandle`]) that owns the opaque handle and calls
//! `cv2x_destroy` on drop.

use std::os::raw::c_int;
use std::ptr;

/// Opaque handle type matching the C `cv2x_handle_t` struct.
#[repr(C)]
pub struct cv2x_handle_t {
    _opaque: [u8; 0],
}

extern "C" {
    pub fn cv2x_init() -> *mut cv2x_handle_t;
    pub fn cv2x_send_sps(h: *mut cv2x_handle_t, data: *const u8, len: usize) -> c_int;
    pub fn cv2x_send_event(h: *mut cv2x_handle_t, data: *const u8, len: usize) -> c_int;
    pub fn cv2x_receive(h: *mut cv2x_handle_t, buf: *mut u8, buf_len: usize) -> c_int;
    pub fn cv2x_get_rx_sock(h: *mut cv2x_handle_t) -> c_int;
    pub fn cv2x_destroy(h: *mut cv2x_handle_t);
}

/// Safe, owning wrapper around the C `cv2x_handle_t *`.
///
/// On `Drop`, the handle is destroyed via `cv2x_destroy()`.
/// The underlying C handle is thread-safe once initialised (each flow uses
/// its own socket FD), so we mark this `Send`.
pub struct Cv2xHandle {
    ptr: *mut cv2x_handle_t,
}

// SAFETY: The opaque C handle owns independent socket file descriptors for
// SPS TX, event TX, and RX.  After initialisation no shared mutable state
// is accessed between threads — each Rust thread uses a distinct FFI
// function (send_sps / send_event / receive) operating on its own socket.
unsafe impl Send for Cv2xHandle {}

// SAFETY: The C functions cv2x_send_sps, cv2x_send_event, and cv2x_receive
// each operate on independent socket file descriptors within the handle.
// Concurrent calls from multiple threads (via &Cv2xHandle through Arc) are
// safe because each socket FD is only used by one thread at a time in our
// architecture (one RX thread, one TX thread).
unsafe impl Sync for Cv2xHandle {}

impl Cv2xHandle {
    /// Initialise the C-V2X radio stack.
    ///
    /// Returns `Some(handle)` on success, `None` if the C layer returned NULL
    /// (radio unavailable, flow creation failure, etc.).
    pub fn new() -> Option<Self> {
        let ptr = unsafe { cv2x_init() };
        if ptr.is_null() {
            None
        } else {
            Some(Cv2xHandle { ptr })
        }
    }

    /// Send a packet via the SPS (Semi-Persistent Scheduling) flow.
    pub fn send_sps(&self, data: &[u8]) -> Result<(), ()> {
        let ret = unsafe { cv2x_send_sps(self.ptr, data.as_ptr(), data.len()) };
        if ret == 0 { Ok(()) } else { Err(()) }
    }

    /// Send a packet via the event-driven flow.
    pub fn send_event(&self, data: &[u8]) -> Result<(), ()> {
        let ret = unsafe { cv2x_send_event(self.ptr, data.as_ptr(), data.len()) };
        if ret == 0 { Ok(()) } else { Err(()) }
    }

    /// Blocking receive.  Returns the received payload, or an error.
    pub fn receive(&self, buf: &mut [u8]) -> Result<usize, ()> {
        let ret = unsafe { cv2x_receive(self.ptr, buf.as_mut_ptr(), buf.len()) };
        if ret >= 0 { Ok(ret as usize) } else { Err(()) }
    }

    /// Return the RX socket file descriptor for use with `poll()`.
    pub fn rx_sock_fd(&self) -> Option<c_int> {
        let fd = unsafe { cv2x_get_rx_sock(self.ptr) };
        if fd >= 0 { Some(fd) } else { None }
    }

    /// Raw pointer accessor (for advanced FFI use only).
    pub fn as_ptr(&self) -> *mut cv2x_handle_t {
        self.ptr
    }
}

impl Drop for Cv2xHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { cv2x_destroy(self.ptr) };
            self.ptr = ptr::null_mut();
        }
    }
}
