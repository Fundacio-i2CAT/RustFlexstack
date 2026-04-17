/*
 * C-compatible wrapper for the Qualcomm Telematics SDK (telux) C-V2X API.
 *
 * Uses the Telux C++ SDK (libtelux_cv2x.so) v1.46.0 which handles:
 *   - QCMAP data call setup (rmnet_data15/rmnet_data16 bring-up)
 *   - QMI service registration
 *   - Flow creation and socket management
 *
 * Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "cv2x_wrapper.h"

#include <cstring>
#include <condition_variable>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <telux/cv2x/Cv2xFactory.hpp>
#include <telux/cv2x/Cv2xRadio.hpp>
#include <telux/cv2x/Cv2xRadioManager.hpp>

/* ── Constants ─────────────────────────────────────────────────────────── */
static constexpr uint32_t SPS_SERVICE_ID  = 1u;
static constexpr uint16_t SPS_SRC_PORT    = 2500u;
static constexpr uint16_t EVENT_SRC_PORT  = 2501u;
static constexpr uint16_t RX_PORT         = 9000u;
static constexpr uint32_t BUF_LEN         = 3000u;
static constexpr int      TX_PRIORITY     = 3;

using namespace telux::cv2x;
using namespace telux::common;

/* ── Opaque handle ─────────────────────────────────────────────────────── */
struct cv2x_handle {
    std::shared_ptr<ICv2xRadioManager>   radioManager;
    std::shared_ptr<ICv2xRadio>          radio;
    std::shared_ptr<ICv2xTxFlow>         spsFlow;
    std::shared_ptr<ICv2xTxFlow>         eventFlow;
    std::shared_ptr<ICv2xRxSubscription> rxSub;
};

/* ── Helpers ───────────────────────────────────────────────────────────── */

/*
 * Send data on a Telux-managed socket with IPV6_TCLASS ancillary data.
 * msg_name is left NULL because the Telux SDK already connects/binds the
 * socket to the correct destination when creating the flow.
 */
static int send_with_priority(int sock, const uint8_t *data, size_t len, int prio)
{
    struct msghdr   message = {};
    struct iovec    iov[1]  = {};
    char            control[CMSG_SPACE(sizeof(int))];
    std::memset(control, 0, sizeof(control));

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
    std::memcpy(CMSG_DATA(cmsghp), &prio, sizeof(int));

    ssize_t ret = sendmsg(sock, &message, 0);
    if (ret < 0) {
        std::cerr << "[cv2x_wrapper] sendmsg failed: " << strerror(errno) << std::endl;
        return -1;
    }
    return 0;
}

/* ── Public C API ──────────────────────────────────────────────────────── */

cv2x_handle_t *rfx_cv2x_init(void)
{
    auto *h = new (std::nothrow) cv2x_handle;
    if (!h) return nullptr;

    /* ── 1. Get Cv2xRadioManager ──────────────────────────────────────── */
    std::cerr << "[cv2x_wrapper] Step 1/4: getting Cv2xRadioManager..." << std::endl;

    bool statusUpdated = false;
    ServiceStatus managerStatus = ServiceStatus::SERVICE_UNAVAILABLE;
    std::condition_variable cv;
    std::mutex mtx;

    auto statusCb = [&](ServiceStatus status) {
        std::lock_guard<std::mutex> lock(mtx);
        statusUpdated = true;
        managerStatus = status;
        cv.notify_all();
    };

    auto &factory = Cv2xFactory::getInstance();
    h->radioManager = factory.getCv2xRadioManager(statusCb);
    if (!h->radioManager) {
        std::cerr << "[cv2x_wrapper] ERROR: getCv2xRadioManager returned null" << std::endl;
        delete h;
        return nullptr;
    }

    {
        std::unique_lock<std::mutex> lck(mtx);
        cv.wait(lck, [&] { return statusUpdated; });
    }

    if (managerStatus != ServiceStatus::SERVICE_AVAILABLE) {
        std::cerr << "[cv2x_wrapper] ERROR: RadioManager not SERVICE_AVAILABLE (status="
                  << static_cast<int>(managerStatus) << ")" << std::endl;
        delete h;
        return nullptr;
    }

    std::cerr << "[cv2x_wrapper] Step 1/4: RadioManager ready" << std::endl;

    /* ── 2. Check radio status ────────────────────────────────────────── */
    std::cerr << "[cv2x_wrapper] Step 2/4: checking radio status..." << std::endl;

    {
        std::promise<ErrorCode> p;
        auto f = p.get_future();
        h->radioManager->requestCv2xStatus(
            [&p](Cv2xStatus status, ErrorCode err) {
                if (err == ErrorCode::SUCCESS) {
                    const char *txNames[] = {"INACTIVE", "ACTIVE", "SUSPENDED"};
                    const char *rxNames[] = {"INACTIVE", "ACTIVE", "SUSPENDED"};
                    int tx = static_cast<int>(status.txStatus);
                    int rx = static_cast<int>(status.rxStatus);
                    std::cerr << "[cv2x_wrapper] TX="
                              << ((tx >= 0 && tx <= 2) ? txNames[tx] : "?")
                              << " RX="
                              << ((rx >= 0 && rx <= 2) ? rxNames[rx] : "?")
                              << std::endl;
                }
                p.set_value(err);
            });
        if (f.get() != ErrorCode::SUCCESS) {
            std::cerr << "[cv2x_wrapper] WARNING: requestCv2xStatus failed" << std::endl;
        }
    }

    /* Get radio handle */
    h->radio = h->radioManager->getCv2xRadio(TrafficCategory::SAFETY_TYPE);
    if (!h->radio) {
        std::cerr << "[cv2x_wrapper] ERROR: getCv2xRadio returned null" << std::endl;
        delete h;
        return nullptr;
    }

    if (!h->radio->isReady()) {
        std::cerr << "[cv2x_wrapper] Waiting for radio to be ready..." << std::endl;
        if (h->radio->onReady().get() != Status::SUCCESS) {
            std::cerr << "[cv2x_wrapper] ERROR: radio failed to become ready" << std::endl;
            delete h;
            return nullptr;
        }
    }

    std::cerr << "[cv2x_wrapper] Step 2/4: radio ready" << std::endl;

    /* ── 3. Create TX flows ───────────────────────────────────────────── */
    std::cerr << "[cv2x_wrapper] Step 3/4: creating TX flows..." << std::endl;

    /* SPS flow (with optional event flow) */
    {
        SpsFlowInfo spsInfo;
        spsInfo.priority         = Priority::PRIORITY_2;
        spsInfo.periodicity      = Periodicity::PERIODICITY_100MS;
        spsInfo.nbytesReserved   = BUF_LEN;
        spsInfo.autoRetransEnabledValid = true;
        spsInfo.autoRetransEnabled      = true;

        std::promise<ErrorCode> p;
        auto f = p.get_future();

        auto rc = h->radio->createTxSpsFlow(
            TrafficIpType::TRAFFIC_NON_IP,
            SPS_SERVICE_ID,
            spsInfo,
            SPS_SRC_PORT,
            true,               /* eventSrcPortValid */
            EVENT_SRC_PORT,     /* eventSrcPort */
            [h, &p](std::shared_ptr<ICv2xTxFlow> spsFlow,
                     std::shared_ptr<ICv2xTxFlow> evtFlow,
                     ErrorCode spsErr,
                     ErrorCode evtErr) {
                if (spsErr == ErrorCode::SUCCESS) {
                    h->spsFlow = spsFlow;
                    std::cerr << "[cv2x_wrapper] SPS flow created (sock="
                              << spsFlow->getSock() << ", port="
                              << spsFlow->getPortNum() << ")" << std::endl;
                }
                if (evtErr == ErrorCode::SUCCESS && evtFlow) {
                    h->eventFlow = evtFlow;
                    std::cerr << "[cv2x_wrapper] Event flow created (sock="
                              << evtFlow->getSock() << ", port="
                              << evtFlow->getPortNum() << ")" << std::endl;
                }
                p.set_value(spsErr);
            });

        if (rc != Status::SUCCESS) {
            std::cerr << "[cv2x_wrapper] ERROR: createTxSpsFlow returned "
                      << static_cast<int>(rc) << std::endl;
            rfx_cv2x_destroy(h);
            return nullptr;
        }

        if (f.get() != ErrorCode::SUCCESS) {
            std::cerr << "[cv2x_wrapper] ERROR: SPS flow creation failed" << std::endl;
            rfx_cv2x_destroy(h);
            return nullptr;
        }
    }

    std::cerr << "[cv2x_wrapper] Step 3/4: TX flows created" << std::endl;

    /* ── 4. Create RX subscription ────────────────────────────────────── */
    std::cerr << "[cv2x_wrapper] Step 4/4: creating RX subscription..." << std::endl;

    {
        std::promise<ErrorCode> p;
        auto f = p.get_future();

        auto rc = h->radio->createRxSubscription(
            TrafficIpType::TRAFFIC_NON_IP,
            RX_PORT,
            [h, &p](std::shared_ptr<ICv2xRxSubscription> rxSub, ErrorCode err) {
                if (err == ErrorCode::SUCCESS && rxSub) {
                    h->rxSub = rxSub;
                    std::cerr << "[cv2x_wrapper] RX subscription created (sock="
                              << rxSub->getSock() << ")" << std::endl;
                }
                p.set_value(err);
            });

        if (rc != Status::SUCCESS) {
            std::cerr << "[cv2x_wrapper] ERROR: createRxSubscription returned "
                      << static_cast<int>(rc) << std::endl;
            rfx_cv2x_destroy(h);
            return nullptr;
        }

        if (f.get() != ErrorCode::SUCCESS) {
            std::cerr << "[cv2x_wrapper] ERROR: RX subscription creation failed" << std::endl;
            rfx_cv2x_destroy(h);
            return nullptr;
        }
    }

    std::cerr << "[cv2x_wrapper] Step 4/4: RX subscription ready" << std::endl;
    std::cerr << "[cv2x_wrapper] Initialisation complete" << std::endl;

    return h;
}

int rfx_cv2x_send_sps(cv2x_handle_t *h, const uint8_t *data, size_t len)
{
    if (!h || !h->spsFlow) return -1;
    return send_with_priority(h->spsFlow->getSock(), data, len, TX_PRIORITY);
}

int rfx_cv2x_send_event(cv2x_handle_t *h, const uint8_t *data, size_t len)
{
    if (!h) return -1;

    /* Prefer event flow; fall back to SPS flow */
    auto &flow = h->eventFlow ? h->eventFlow : h->spsFlow;
    if (!flow) return -1;

    return send_with_priority(flow->getSock(), data, len, TX_PRIORITY);
}

int rfx_cv2x_receive(cv2x_handle_t *h, uint8_t *buf, size_t buf_len)
{
    if (!h || !h->rxSub) return -1;
    ssize_t n = recv(h->rxSub->getSock(), buf, buf_len, 0);
    return (n >= 0) ? static_cast<int>(n) : -1;
}

int rfx_cv2x_get_rx_sock(cv2x_handle_t *h)
{
    if (!h || !h->rxSub) return -1;
    return h->rxSub->getSock();
}

void rfx_cv2x_destroy(cv2x_handle_t *h)
{
    if (!h) return;

    /* Close TX flows and RX subscription via the SDK so the modem deregisters
     * flows properly (matching what acme does on Ctrl+C). */
    if (h->radio) {
        if (h->spsFlow) {
            std::promise<ErrorCode> p;
            auto f = p.get_future();
            h->radio->closeTxFlow(h->spsFlow,
                [&p](std::shared_ptr<ICv2xTxFlow>, ErrorCode err) {
                    p.set_value(err);
                });
            f.get();
            h->spsFlow.reset();
        }

        if (h->eventFlow) {
            std::promise<ErrorCode> p;
            auto f = p.get_future();
            h->radio->closeTxFlow(h->eventFlow,
                [&p](std::shared_ptr<ICv2xTxFlow>, ErrorCode err) {
                    p.set_value(err);
                });
            f.get();
            h->eventFlow.reset();
        }

        if (h->rxSub) {
            std::promise<ErrorCode> p;
            auto f = p.get_future();
            h->radio->closeRxSubscription(h->rxSub,
                [&p](std::shared_ptr<ICv2xRxSubscription>, ErrorCode err) {
                    p.set_value(err);
                });
            f.get();
            h->rxSub.reset();
        }
    }

    delete h;
}
