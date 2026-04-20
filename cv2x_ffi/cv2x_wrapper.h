/*
 * C-compatible wrapper for the Qualcomm Telematics SDK (telux) C-V2X API.
 *
 * This thin layer exposes the telux C++ API through a pure C interface so that
 * Rust (or any language with a C FFI) can initialise the radio, create SPS and
 * event TX flows, and receive packets — without needing a C++ compiler on the
 * Rust side.
 *
 * Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CV2X_WRAPPER_H
#define CV2X_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle — the actual struct lives in the .cpp translation unit. */
typedef struct cv2x_handle cv2x_handle_t;

/*
 * Initialise the C-V2X radio stack.
 *
 * This blocks until the radio manager reports SERVICE_AVAILABLE, then creates:
 *   - one SPS TX flow    (service_id=1, port=2500, 100 ms, 3000 B, PRIORITY_2)
 *   - one event TX flow  (service_id=1, port=2501)
 *   - one RX subscription (port=9000, wildcard service ID)
 *
 * Returns a heap-allocated handle on success, or NULL on failure.
 * The caller must eventually call cv2x_destroy() to release resources.
 */
cv2x_handle_t *rfx_cv2x_init(void);

/*
 * Send a packet through the SPS (Semi-Persistent Scheduling) TX flow.
 * Use this for periodic messages such as CAMs.
 *
 * Returns 0 on success, -1 on error.
 */
int rfx_cv2x_send_sps(cv2x_handle_t *h, const uint8_t *data, size_t len);

/*
 * Send a packet through the event-driven TX flow.
 * Use this for sporadic messages such as DENMs or VAMs.
 *
 * Returns 0 on success, -1 on error.
 */
int rfx_cv2x_send_event(cv2x_handle_t *h, const uint8_t *data, size_t len);

/*
 * Blocking receive from the RX subscription.
 *
 * Reads up to buf_len bytes into buf.
 * Returns the number of bytes received on success, or -1 on error.
 */
int rfx_cv2x_receive(cv2x_handle_t *h, uint8_t *buf, size_t buf_len);

/*
 * Return the raw RX socket file descriptor.
 * Useful for poll()/select() in the caller's event loop.
 *
 * Returns the fd on success, or -1 if the handle is invalid.
 */
int rfx_cv2x_get_rx_sock(cv2x_handle_t *h);

/*
 * Tear down all flows and subscriptions, then free the handle.
 * Safe to call with NULL (no-op).
 */
void rfx_cv2x_destroy(cv2x_handle_t *h);

#ifdef __cplusplus
}
#endif

#endif /* CV2X_WRAPPER_H */
