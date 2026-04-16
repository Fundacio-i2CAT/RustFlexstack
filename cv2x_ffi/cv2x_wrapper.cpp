/*
 * C-compatible wrapper for the Qualcomm Telematics SDK (telux) C-V2X API.
 *
 * Implements the interface declared in cv2x_wrapper.h.  The logic mirrors
 * cv2x_link_layer.cpp but exposes separate SPS and event TX paths and avoids
 * any pybind11 dependency.
 *
 * Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "cv2x_wrapper.h"

#include <array>
#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <telux/cv2x/Cv2xRadio.hpp>

using std::promise;
using std::shared_ptr;
using telux::common::ErrorCode;
using telux::common::Status;
using telux::cv2x::Cv2xStatus;
using telux::cv2x::Cv2xStatusType;
using telux::cv2x::ICv2xRadio;
using telux::cv2x::ICv2xRxSubscription;
using telux::cv2x::ICv2xTxFlow;
using telux::cv2x::Periodicity;
using telux::cv2x::Priority;
using telux::cv2x::SpsFlowInfo;
using telux::cv2x::TrafficCategory;
using telux::cv2x::TrafficIpType;

/* ── Public Cv2xFactory (declared in Cv2xFactory.hpp, included via Cv2xRadio.hpp) ── */

/* ── Constants ─────────────────────────────────────────────────────────── */
static constexpr uint32_t SPS_SERVICE_ID    = 1u;
static constexpr uint16_t SPS_SRC_PORT      = 2500u;
static constexpr uint16_t EVENT_SRC_PORT    = 2501u;
static constexpr uint16_t RX_PORT           = 9000u;
static constexpr uint32_t BUF_LEN           = 3000u;
static constexpr int       TX_PRIORITY      = 3;

/* ── Opaque handle definition ──────────────────────────────────────────── */
struct cv2x_handle {
    shared_ptr<ICv2xRadio>           radio;
    shared_ptr<ICv2xTxFlow>          sps_flow;
    shared_ptr<ICv2xTxFlow>          event_flow;
    shared_ptr<ICv2xRxSubscription>  rx_sub;
    Cv2xStatus                       status;
    promise<ErrorCode>               cb_promise;
};

/* ── Internal helpers ──────────────────────────────────────────────────── */

/**
 * Send a datagram on the given socket fd using sendmsg() with IPV6_TCLASS
 * ancillary data (required by the telux non-IP socket interface).
 */
static int send_on_sock(int sock, const uint8_t *data, size_t len, int priority)
{
    struct msghdr   message = {};
    struct iovec    iov[1]  = {};
    char            control[CMSG_SPACE(sizeof(int))];

    iov[0].iov_base = const_cast<uint8_t *>(data);
    iov[0].iov_len  = len;

    message.msg_iov        = iov;
    message.msg_iovlen     = 1;
    message.msg_control    = control;
    message.msg_controllen = sizeof(control);

    struct cmsghdr *cmsghp = CMSG_FIRSTHDR(&message);
    cmsghp->cmsg_level = IPPROTO_IPV6;
    cmsghp->cmsg_type  = IPV6_TCLASS;
    cmsghp->cmsg_len   = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsghp), &priority, sizeof(int));

    return (sendmsg(sock, &message, 0) >= 0) ? 0 : -1;
}

/* ── Public C API ──────────────────────────────────────────────────────── */

cv2x_handle_t *cv2x_init(void)
{
    auto h = new (std::nothrow) cv2x_handle();
    if (!h) return nullptr;

    try {
        /* ── 1. Radio manager ──────────────────────────────────────────── */
        auto &factory = telux::cv2x::Cv2xFactory::getInstance();
        auto  mgr     = factory.getCv2xRadioManager();
        if (!mgr) throw std::runtime_error("getCv2xRadioManager returned null");

        if (!mgr->onReady().get())
            throw std::runtime_error("Radio manager not available");

        /* ── 2. Request C-V2X status ───────────────────────────────────── */
        h->cb_promise = promise<ErrorCode>();
        auto stat_cb  = [h](Cv2xStatus st, ErrorCode err) {
            if (err == ErrorCode::SUCCESS) h->status = st;
            h->cb_promise.set_value(err);
        };
        if (Status::SUCCESS != mgr->requestCv2xStatus(stat_cb))
            throw std::runtime_error("requestCv2xStatus failed");
        if (ErrorCode::SUCCESS != h->cb_promise.get_future().get())
            throw std::runtime_error("CV2X status error");

        /* ── 3. Get radio handle (SAFETY_TYPE) ─────────────────────────── */
        h->radio = mgr->getCv2xRadio(TrafficCategory::SAFETY_TYPE);
        if (!h->radio->isReady()) {
            if (Status::SUCCESS != h->radio->onReady().get())
                throw std::runtime_error("Radio onReady failed");
        }

        /* ── 4. Create combined SPS + event TX flow ────────────────────── */
        SpsFlowInfo sps_info;
        sps_info.priority                = Priority::PRIORITY_2;
        sps_info.periodicity             = Periodicity::PERIODICITY_100MS;
        sps_info.nbytesReserved          = BUF_LEN;
        sps_info.autoRetransEnabledValid = true;
        sps_info.autoRetransEnabled      = true;

        h->cb_promise = promise<ErrorCode>();
        auto sps_cb   = [h](shared_ptr<ICv2xTxFlow> sps,
                          shared_ptr<ICv2xTxFlow> evt,
                          ErrorCode sps_err,
                          ErrorCode evt_err) {
            if (sps_err == ErrorCode::SUCCESS) h->sps_flow   = sps;
            if (evt_err == ErrorCode::SUCCESS) h->event_flow  = evt;
            /* Report the SPS error; the event flow is best-effort. */
            h->cb_promise.set_value(sps_err);
        };

        if (Status::SUCCESS !=
            h->radio->createTxSpsFlow(
                TrafficIpType::TRAFFIC_NON_IP,
                SPS_SERVICE_ID,
                sps_info,
                SPS_SRC_PORT,
                true,               /* eventSrcPortValid — create event flow too */
                EVENT_SRC_PORT,
                sps_cb))
        {
            throw std::runtime_error("createTxSpsFlow failed");
        }
        if (ErrorCode::SUCCESS != h->cb_promise.get_future().get())
            throw std::runtime_error("SPS flow creation error");

        /* If the event flow was not created (older firmware), log but continue */
        if (!h->event_flow) {
            std::cerr << "[cv2x_wrapper] Warning: event flow not created; "
                         "all TX will use SPS flow\n";
        }

        /* ── 5. Create RX subscription ─────────────────────────────────── */
        h->cb_promise = promise<ErrorCode>();
        auto rx_cb    = [h](shared_ptr<ICv2xRxSubscription> sub, ErrorCode err) {
            if (err == ErrorCode::SUCCESS) h->rx_sub = sub;
            h->cb_promise.set_value(err);
        };
        if (Status::SUCCESS !=
            h->radio->createRxSubscription(
                TrafficIpType::TRAFFIC_NON_IP,
                RX_PORT,
                rx_cb))
        {
            throw std::runtime_error("createRxSubscription failed");
        }
        if (ErrorCode::SUCCESS != h->cb_promise.get_future().get())
            throw std::runtime_error("RX subscription error");

    } catch (const std::exception &ex) {
        std::cerr << "[cv2x_wrapper] init error: " << ex.what() << "\n";
        delete h;
        return nullptr;
    }

    return h;
}

int cv2x_send_sps(cv2x_handle_t *h, const uint8_t *data, size_t len)
{
    if (!h || !h->sps_flow) return -1;
    return send_on_sock(h->sps_flow->getSock(), data, len, TX_PRIORITY);
}

int cv2x_send_event(cv2x_handle_t *h, const uint8_t *data, size_t len)
{
    if (!h) return -1;
    /* Fall back to SPS flow if event flow was not created */
    auto &flow = h->event_flow ? h->event_flow : h->sps_flow;
    if (!flow) return -1;
    return send_on_sock(flow->getSock(), data, len, TX_PRIORITY);
}

int cv2x_receive(cv2x_handle_t *h, uint8_t *buf, size_t buf_len)
{
    if (!h || !h->rx_sub) return -1;
    int sock = h->rx_sub->getSock();
    ssize_t n = recv(sock, buf, buf_len, 0);
    return (n >= 0) ? static_cast<int>(n) : -1;
}

int cv2x_get_rx_sock(cv2x_handle_t *h)
{
    if (!h || !h->rx_sub) return -1;
    return h->rx_sub->getSock();
}

void cv2x_destroy(cv2x_handle_t *h)
{
    if (!h) return;

    if (h->radio) {
        /* Close SPS flow */
        if (h->sps_flow) {
            h->cb_promise = promise<ErrorCode>();
            h->radio->closeTxFlow(
                h->sps_flow,
                [h](shared_ptr<ICv2xTxFlow>, ErrorCode err) {
                    h->cb_promise.set_value(err);
                });
            h->cb_promise.get_future().get();
        }

        /* Close event flow */
        if (h->event_flow) {
            h->cb_promise = promise<ErrorCode>();
            h->radio->closeTxFlow(
                h->event_flow,
                [h](shared_ptr<ICv2xTxFlow>, ErrorCode err) {
                    h->cb_promise.set_value(err);
                });
            h->cb_promise.get_future().get();
        }

        /* Close RX subscription */
        if (h->rx_sub) {
            h->cb_promise = promise<ErrorCode>();
            h->radio->closeRxSubscription(
                h->rx_sub,
                [h](shared_ptr<ICv2xRxSubscription>, ErrorCode err) {
                    h->cb_promise.set_value(err);
                });
            h->cb_promise.get_future().get();
        }
    }

    delete h;
}
