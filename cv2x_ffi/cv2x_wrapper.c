/*
 * C-compatible wrapper for the Qualcomm C-V2X direct QMI API.
 *
 * Uses the cv2x-qmi library (libcv2x-qmi.so) which communicates directly
 * with the modem via QMI — the same path that cv2x-config uses.
 * This bypasses both the Telux C++ SDK and the libv2x_radio wrapper,
 * which hang on MK6 ag550 devices because the Telux radio manager
 * never reaches SERVICE_AVAILABLE.
 *
 * Prerequisites:
 *   - cv2x-daemon must be running (it sets up rmnet data calls)
 *   - rmnet_data16 interface must be UP (non-IP V2X data path)
 *
 * Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "cv2x_wrapper.h"

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Forward declarations from libcv2x-qmi (cv2x-qmi.h) ─────────────── *
 *
 * We declare only what we need to avoid pulling in the full header chain
 * (dsi_netctrl.h → qos → qmi → v2x_radio_api.h → pb.h etc.).
 */

/* Opaque QMI client handle — defined in qmi_client.h as a void* */
typedef void *qmi_client_type;

/* Forward‐declare the cv2x_state_t struct (opaque to us) */
typedef struct cv2x_state cv2x_state_t;

/* Status enum from cv2x-qmi.h */
typedef enum {
    CV2X_STATUS_INACTIVE = 0,
    CV2X_STATUS_ACTIVE,
    CV2X_STATUS_SUSPENDED,
} cv2x_status_enum_t;

typedef enum {
    CV2X_STATUS_CAUSE_TIMING_INVALID = 0,
    CV2X_STATUS_CAUSE_CONFIG_INVALID,
    CV2X_STATUS_CAUSE_UE_MODE_INVALID,
    CV2X_STATUS_CAUSE_OUT_OF_ALLOWED_GEOPOLYGON,
} cv2x_status_cause_enum_t;

typedef struct {
    uint8_t tx_status_valid;
    cv2x_status_enum_t tx_status;
    uint8_t rx_status_valid;
    cv2x_status_enum_t rx_status;
    uint8_t cbr_value_valid;
    uint8_t cbr_value;
    uint8_t tx_cause_valid;
    cv2x_status_cause_enum_t tx_cause;
    uint8_t rx_cause_valid;
    cv2x_status_cause_enum_t rx_cause;
    /* remaining fields we don't use */
    uint8_t _padding[128];
} cv2x_status_t;

typedef void (*cv2x_status_cb_t)(cv2x_status_t status);

typedef enum {
    CV2X_RETX_AUTO = 0,
    CV2X_RETX_ON,
    CV2X_RETX_OFF,
} retx_enum_t;

typedef struct {
    uint32_t service_id;
    uint8_t priority;
    uint32_t periodicity;
    uint32_t msg_size;
    uint16_t sps_port;
    uint8_t non_sps_port_valid;
    uint16_t non_sps_port;
    uint8_t tx_pool_id_valid;
    uint8_t tx_pool_id;
    uint8_t peak_tx_power_valid;
    int32_t peak_tx_power;
    uint8_t mcs_index_valid;
    uint8_t mcs_index;
    uint8_t retx_setting_valid;
    retx_enum_t retx_setting;
} sps_flow_t;

typedef struct {
    uint32_t service_id;
    uint16_t port;
    uint8_t tx_pool_id_valid;
    uint8_t tx_pool_id;
    uint8_t peak_tx_power_valid;
    int32_t peak_tx_power;
    uint8_t mcs_index_valid;
    uint8_t mcs_index;
    uint8_t retx_setting_valid;
    retx_enum_t retx_setting;
} non_sps_flow_t;

/* Functions from libcv2x-qmi.so */
extern cv2x_state_t *init_v2x_library(void);
extern void          deinit_v2x_library(cv2x_state_t *state);
extern int           init_qmi_services(cv2x_state_t *state);
extern void          deinit_qmi_services(cv2x_state_t *state);
extern int           get_v2x_radio_status(qmi_client_type client,
                                          cv2x_status_t *status,
                                          cv2x_state_t *state);
extern int           start_v2x_radio(qmi_client_type client);
extern int           stop_v2x_radio(qmi_client_type client);
extern int           register_v2x_sps_flow(qmi_client_type client,
                                           uint32_t req_id,
                                           sps_flow_t flow,
                                           uint8_t *sps_id);
extern int           deregister_v2x_sps_flow(qmi_client_type client,
                                             uint32_t req_id,
                                             uint8_t sps_id);
extern int           register_v2x_non_sps_flow(qmi_client_type client,
                                               uint32_t req_id,
                                               non_sps_flow_t flow);
extern int           subscribe_v2x_service_wildcard(qmi_client_type client,
                                                    uint32_t req_id,
                                                    uint16_t port);
extern int           unsubscribe_v2x_service_wildcard(qmi_client_type client,
                                                      uint32_t req_id);
extern void          subscribe_v2x_status_callback(cv2x_state_t *state,
                                                   cv2x_status_cb_t callback);

/* traffic_ip_type_t from v2x_radio_api.h */
typedef enum {
    TRAFFIC_IP     = 0,
    TRAFFIC_NON_IP = 1,
} traffic_ip_type_t;

/* WDS (Wireless Data Service) functions — needed to set up the data call
 * before flows can be registered. */
extern qmi_client_type get_wds_client_by_interface(traffic_ip_type_t type,
                                                   cv2x_state_t *state);
extern int             register_wds_callback(qmi_client_type client);

/*
 * cv2x_state_t field offsets — we need access to the QMI client handles
 * stored inside.  The struct layout (from cv2x-qmi.h):
 *
 *   struct cv2x_state {
 *       qmi_client_type nas_client;              // offset 0
 *       qmi_client_os_params nas_os_params;       // offset 8
 *       qmi_client_ind_cb nas_callback;            // offset ...
 *       qmi_client_type wds_client;
 *       ...
 *   };
 *
 * On aarch64, qmi_client_type is void*, qmi_client_os_params is a struct
 * containing an os_params union (4 bytes on linux) padded to 8.
 * We access the nas_client as the first pointer in the struct.
 */

/* Helper: access nas_client (first field of cv2x_state_t) */
static inline qmi_client_type get_nas_client(cv2x_state_t *state) {
    /* nas_client is the first member: struct cv2x_state { qmi_client_type nas_client; ...} */
    return *(qmi_client_type *)state;
}

/* ── Constants ─────────────────────────────────────────────────────────── */
#define V2X_NON_IP_IFACE "rmnet_data16"
static const uint32_t SPS_SERVICE_ID      = 1u;
static const uint16_t SPS_SRC_PORT        = 2500u;
static const uint16_t EVENT_SRC_PORT      = 2501u;
static const uint16_t RX_PORT             = 9000u;
static const uint32_t BUF_LEN             = 3000u;
static const int      TX_PRIORITY_INT     = 3;

/* ── Opaque handle definition ──────────────────────────────────────────── */
struct cv2x_handle {
    cv2x_state_t       *qmi_state;
    int                 sps_sock;
    int                 event_sock;
    int                 rx_sock;
    struct sockaddr_in6 sps_addr;
    struct sockaddr_in6 event_addr;
    struct sockaddr_in6 rx_addr;
    uint8_t             sps_id;
    bool                sps_registered;
};

/* ── Internal helpers ──────────────────────────────────────────────────── */

/**
 * Create a UDP6 socket bound to the V2X non-IP interface (rmnet_data16)
 * on a specific port.  Returns the fd or -1 on error.
 *
 * out_addr is filled with the *destination* address for sendmsg —
 * the interface's global IPv6 address on the V2X port.
 */
static int create_v2x_sock(uint16_t port, struct sockaddr_in6 *out_addr)
{
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        fprintf(stderr, "[cv2x_wrapper] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    /* Get interface index for scopeid */
    unsigned int if_index = if_nametoindex(V2X_NON_IP_IFACE);
    if (if_index == 0) {
        fprintf(stderr, "[cv2x_wrapper] if_nametoindex(%s) failed: %s\n",
                V2X_NON_IP_IFACE, strerror(errno));
        close(fd);
        return -1;
    }

    /* Bind to the non-IP interface via SO_BINDTODEVICE (needs CAP_NET_RAW)
     * or fall back to binding with scope_id only */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, V2X_NON_IP_IFACE, IFNAMSIZ - 1);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        fprintf(stderr, "[cv2x_wrapper] SO_BINDTODEVICE(%s): %s (will use scope_id only)\n",
                V2X_NON_IP_IFACE, strerror(errno));
    }

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family   = AF_INET6;
    addr.sin6_port     = htons(port);
    addr.sin6_addr     = in6addr_any;       /* :: — wildcard; scoped to iface via scope_id */
    addr.sin6_scope_id = if_index;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[cv2x_wrapper] bind(port=%u) failed: %s\n",
                port, strerror(errno));
        close(fd);
        return -1;
    }

    /* Build the destination address for sendmsg.  Use the interface's global
     * IPv6 address so the packet routes to rmnet_data16 and the modem
     * driver picks it up for PC5 sidelink transmission. */
    if (out_addr) {
        memset(out_addr, 0, sizeof(*out_addr));
        out_addr->sin6_family   = AF_INET6;
        out_addr->sin6_port     = htons(port);
        out_addr->sin6_scope_id = if_index;

        /* Look up the global IPv6 address of rmnet_data16 */
        struct ifaddrs *ifap = NULL, *ifa;
        bool found = false;
        if (getifaddrs(&ifap) == 0) {
            for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                if (ifa->ifa_addr->sa_family != AF_INET6) continue;
                if (strcmp(ifa->ifa_name, V2X_NON_IP_IFACE) != 0) continue;
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                /* Skip link-local (fe80::) — we want the global address */
                if (IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) continue;
                out_addr->sin6_addr = s6->sin6_addr;
                found = true;
                break;
            }
            freeifaddrs(ifap);
        }
        if (!found) {
            fprintf(stderr, "[cv2x_wrapper] WARNING: no global IPv6 address on %s, "
                    "using in6addr_any for destination\n", V2X_NON_IP_IFACE);
            out_addr->sin6_addr = in6addr_any;
        }
    }
    return fd;
}

/**
 * Send a datagram with IPV6_TCLASS ancillary data (priority).
 */
static int send_on_sock(int sock, const struct sockaddr_in6 *dst,
                        const uint8_t *data, size_t len, int priority)
{
    struct msghdr   message;
    struct iovec    iov[1];
    char            control[CMSG_SPACE(sizeof(int))];

    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));

    iov[0].iov_base = (void *)data;
    iov[0].iov_len  = len;

    message.msg_name       = (void *)dst;
    message.msg_namelen    = sizeof(*dst);
    message.msg_iov        = iov;
    message.msg_iovlen     = 1;
    message.msg_control    = control;
    message.msg_controllen = sizeof(control);

    struct cmsghdr *cmsghp = CMSG_FIRSTHDR(&message);
    cmsghp->cmsg_level = IPPROTO_IPV6;
    cmsghp->cmsg_type  = IPV6_TCLASS;
    cmsghp->cmsg_len   = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsghp), &priority, sizeof(int));

    ssize_t ret = sendmsg(sock, &message, 0);
    if (ret < 0) {
        fprintf(stderr, "[cv2x_wrapper] sendmsg failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* ── Status callback ───────────────────────────────────────────────────── */
static void status_cb(cv2x_status_t status)
{
    const char *tx_names[] = {"INACTIVE", "ACTIVE", "SUSPENDED"};
    const char *rx_names[] = {"INACTIVE", "ACTIVE", "SUSPENDED"};
    const char *tx = (status.tx_status <= 2) ? tx_names[status.tx_status] : "?";
    const char *rx = (status.rx_status <= 2) ? rx_names[status.rx_status] : "?";
    fprintf(stderr, "[cv2x_wrapper] status: TX=%s RX=%s\n", tx, rx);
}

/* ── Public C API ──────────────────────────────────────────────────────── */

cv2x_handle_t *cv2x_init(void)
{
    struct cv2x_handle *h = (struct cv2x_handle *)calloc(1, sizeof(*h));
    if (!h) return NULL;

    h->sps_sock     = -1;
    h->event_sock   = -1;
    h->rx_sock      = -1;
    h->sps_registered = false;

    /* ── 1. Initialise QMI library ────────────────────────────────────── */
    fprintf(stderr, "[cv2x_wrapper] Step 1/4: initialising QMI library...\n");

    h->qmi_state = init_v2x_library();
    if (!h->qmi_state) {
        fprintf(stderr, "[cv2x_wrapper] ERROR: init_v2x_library() failed\n");
        goto fail;
    }

    int rc = init_qmi_services(h->qmi_state);
    if (rc != 0) {
        fprintf(stderr, "[cv2x_wrapper] ERROR: init_qmi_services() failed (rc=%d)\n", rc);
        goto fail;
    }

    /* Register status callback */
    subscribe_v2x_status_callback(h->qmi_state, status_cb);

    /* Initialise WDS (Wireless Data Service) clients — this sets up the data
     * calls on rmnet interfaces and is required before flows can be registered. */
    qmi_client_type wds_ip = get_wds_client_by_interface(TRAFFIC_IP, h->qmi_state);
    if (wds_ip) {
        register_wds_callback(wds_ip);
    } else {
        fprintf(stderr, "[cv2x_wrapper] WARNING: get_wds_client_by_interface(IP) returned NULL\n");
    }
    qmi_client_type wds_non_ip = get_wds_client_by_interface(TRAFFIC_NON_IP, h->qmi_state);
    if (wds_non_ip) {
        register_wds_callback(wds_non_ip);
    } else {
        fprintf(stderr, "[cv2x_wrapper] WARNING: get_wds_client_by_interface(NON_IP) returned NULL\n");
    }

    fprintf(stderr, "[cv2x_wrapper] Step 1/4: QMI library initialised\n");

    /* ── 2. Check/start radio ─────────────────────────────────────────── */
    fprintf(stderr, "[cv2x_wrapper] Step 2/4: checking radio status...\n");

    qmi_client_type nas = get_nas_client(h->qmi_state);
    cv2x_status_t st;
    memset(&st, 0, sizeof(st));
    rc = get_v2x_radio_status(nas, &st, h->qmi_state);

    if (rc == 0) {
        fprintf(stderr, "[cv2x_wrapper] current status: TX=%d RX=%d\n",
                st.tx_status, st.rx_status);
    } else {
        fprintf(stderr, "[cv2x_wrapper] WARNING: get_v2x_radio_status failed (rc=%d), "
                "attempting start anyway\n", rc);
    }

    /* Try to start radio — may already be started by cv2x-daemon */
    rc = start_v2x_radio(nas);
    if (rc == 0) {
        fprintf(stderr, "[cv2x_wrapper] Step 2/4: radio started (or already running)\n");
    } else {
        /* Error code 3 = already started — that's fine */
        fprintf(stderr, "[cv2x_wrapper] Step 2/4: start_v2x_radio rc=%d "
                "(non-zero may mean already started)\n", rc);
    }

    /* ── 3. Register SPS flow + subscribe wildcard RX ─────────────────── */
    fprintf(stderr, "[cv2x_wrapper] Step 3/4: registering flows...\n");

    sps_flow_t sps_flow;
    memset(&sps_flow, 0, sizeof(sps_flow));
    sps_flow.service_id       = SPS_SERVICE_ID;
    sps_flow.priority         = 2;
    sps_flow.periodicity      = 100;
    sps_flow.msg_size         = BUF_LEN;
    sps_flow.sps_port         = SPS_SRC_PORT;
    sps_flow.non_sps_port_valid = 1;
    sps_flow.non_sps_port     = EVENT_SRC_PORT;

    rc = register_v2x_sps_flow(nas, 1, sps_flow, &h->sps_id);
    if (rc != 0) {
        fprintf(stderr, "[cv2x_wrapper] WARNING: register_v2x_sps_flow failed (rc=%d), "
                "TX may not work\n", rc);
    } else {
        h->sps_registered = true;
        fprintf(stderr, "[cv2x_wrapper] SPS flow registered (sps_id=%u)\n", h->sps_id);
    }

    /* Subscribe wildcard RX on port 9000 */
    rc = subscribe_v2x_service_wildcard(nas, 2, RX_PORT);
    if (rc != 0) {
        fprintf(stderr, "[cv2x_wrapper] WARNING: subscribe_v2x_service_wildcard failed "
                "(rc=%d), RX may not work\n", rc);
    } else {
        fprintf(stderr, "[cv2x_wrapper] Wildcard RX subscription registered (port=%u)\n",
                RX_PORT);
    }

    fprintf(stderr, "[cv2x_wrapper] Step 3/4: flows registered\n");

    /* ── 4. Create UDP6 sockets on rmnet_data16 ──────────────────────── */
    fprintf(stderr, "[cv2x_wrapper] Step 4/4: creating sockets on %s...\n",
            V2X_NON_IP_IFACE);

    h->sps_sock = create_v2x_sock(SPS_SRC_PORT, &h->sps_addr);
    if (h->sps_sock < 0) {
        fprintf(stderr, "[cv2x_wrapper] ERROR: SPS socket creation failed\n");
        goto fail;
    }

    h->event_sock = create_v2x_sock(EVENT_SRC_PORT, &h->event_addr);
    if (h->event_sock < 0) {
        fprintf(stderr, "[cv2x_wrapper] WARNING: event socket creation failed, "
                "will use SPS socket for events\n");
    }

    h->rx_sock = create_v2x_sock(RX_PORT, &h->rx_addr);
    if (h->rx_sock < 0) {
        fprintf(stderr, "[cv2x_wrapper] ERROR: RX socket creation failed\n");
        goto fail;
    }

    fprintf(stderr, "[cv2x_wrapper] Step 4/4: sockets created "
            "(sps=%d, event=%d, rx=%d)\n",
            h->sps_sock, h->event_sock, h->rx_sock);
    fprintf(stderr, "[cv2x_wrapper] Initialisation complete\n");

    return h;

fail:
    cv2x_destroy(h);
    return NULL;
}

int cv2x_send_sps(cv2x_handle_t *h, const uint8_t *data, size_t len)
{
    if (!h || h->sps_sock < 0) return -1;
    return send_on_sock(h->sps_sock, &h->sps_addr, data, len, TX_PRIORITY_INT);
}

int cv2x_send_event(cv2x_handle_t *h, const uint8_t *data, size_t len)
{
    if (!h) return -1;
    int sock = (h->event_sock >= 0) ? h->event_sock : h->sps_sock;
    if (sock < 0) return -1;
    const struct sockaddr_in6 *addr = (h->event_sock >= 0)
                                      ? &h->event_addr : &h->sps_addr;
    return send_on_sock(sock, addr, data, len, TX_PRIORITY_INT);
}

int cv2x_receive(cv2x_handle_t *h, uint8_t *buf, size_t buf_len)
{
    if (!h || h->rx_sock < 0) return -1;
    ssize_t n = recv(h->rx_sock, buf, buf_len, 0);
    return (n >= 0) ? (int)n : -1;
}

int cv2x_get_rx_sock(cv2x_handle_t *h)
{
    if (!h) return -1;
    return h->rx_sock;
}

void cv2x_destroy(cv2x_handle_t *h)
{
    if (!h) return;

    if (h->sps_sock >= 0) close(h->sps_sock);
    if (h->event_sock >= 0) close(h->event_sock);
    if (h->rx_sock >= 0) close(h->rx_sock);

    if (h->qmi_state) {
        if (h->sps_registered) {
            qmi_client_type nas = get_nas_client(h->qmi_state);
            unsubscribe_v2x_service_wildcard(nas, 2);
            deregister_v2x_sps_flow(nas, 1, h->sps_id);
        }
        deinit_qmi_services(h->qmi_state);
        deinit_v2x_library(h->qmi_state);
    }

    free(h);
}
