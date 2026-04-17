/*
 * Minimal standalone test: calls cv2x_init(), sends a dummy packet,
 * then cv2x_destroy().  Compiled directly against sysroot-mk6 headers
 * and linked with libtelux_cv2x.so to verify the wrapper works
 * independently of Rust.
 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include "cv2x_wrapper.h"

int main(void)
{
    fprintf(stderr, "=== test_cv2x: standalone C wrapper test ===\n");

    cv2x_handle_t *h = rfx_cv2x_init();
    if (!h) {
        fprintf(stderr, "rfx_cv2x_init() failed (returned NULL)\n");
        return 1;
    }
    fprintf(stderr, "rfx_cv2x_init() succeeded!\n");

    /* Send 10 dummy SPS packets */
    uint8_t buf[128];
    memset(buf, 0x42, sizeof(buf));
    for (int i = 0; i < 10; i++) {
        buf[0] = (uint8_t)i;
        int rc = rfx_cv2x_send_sps(h, buf, sizeof(buf));
        fprintf(stderr, "rfx_cv2x_send_sps[%d] = %d\n", i, rc);
        usleep(100000);  /* 100 ms */
    }

    fprintf(stderr, "Cleaning up...\n");
    rfx_cv2x_destroy(h);
    fprintf(stderr, "Done.\n");
    return 0;
}
