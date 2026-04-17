/*
 * Minimal test — reproduces the snaptel sample's exact init pattern
 * to see if the hang is in our cv2x_wrapper or somewhere deeper.
 */
#include <iostream>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <memory>
#include <unistd.h>

#include <telux/cv2x/Cv2xRadio.hpp>

using namespace telux::cv2x;
using namespace telux::common;

int main()
{
    std::cerr << "=== minimal_cv2x_test pid=" << getpid() << " ===" << std::endl;

    /* Exactly mirror the snaptel sample */
    bool cv2xRadioManagerStatusUpdated = false;
    ServiceStatus cv2xRadioManagerStatus = ServiceStatus::SERVICE_UNAVAILABLE;
    std::condition_variable cv;
    std::mutex mtx;

    auto statusCb = [&](ServiceStatus status) {
        std::cerr << "[test] statusCb fired, status=" << static_cast<int>(status)
                  << " pid=" << getpid() << std::endl;
        std::lock_guard<std::mutex> lock(mtx);
        cv2xRadioManagerStatusUpdated = true;
        cv2xRadioManagerStatus = status;
        cv.notify_all();
    };

    std::cerr << "[test] calling Cv2xFactory::getInstance()..." << std::endl;
    auto &cv2xFactory = Cv2xFactory::getInstance();

    std::cerr << "[test] calling getCv2xRadioManager()..." << std::endl;
    auto cv2xRadioManager = cv2xFactory.getCv2xRadioManager(statusCb);
    if (!cv2xRadioManager) {
        std::cerr << "[test] getCv2xRadioManager returned null" << std::endl;
        return 1;
    }

    std::cerr << "[test] waiting for status callback..." << std::endl;
    {
        std::unique_lock<std::mutex> lck(mtx);
        cv.wait(lck, [&] { return cv2xRadioManagerStatusUpdated; });
    }

    std::cerr << "[test] status = " << static_cast<int>(cv2xRadioManagerStatus) << std::endl;

    if (ServiceStatus::SERVICE_AVAILABLE != cv2xRadioManagerStatus) {
        std::cerr << "[test] RadioManager NOT AVAILABLE" << std::endl;
        return 1;
    }

    std::cerr << "[test] RadioManager ready, requesting Cv2x status..." << std::endl;

    /* Check radio status */
    auto cv2xRadio = cv2xRadioManager->getCv2xRadio(TrafficCategory::SAFETY_TYPE);
    if (!cv2xRadio) {
        std::cerr << "[test] getCv2xRadio returned null" << std::endl;
        return 1;
    }

    if (!cv2xRadio->isReady()) {
        std::cerr << "[test] waiting for radio ready..." << std::endl;
        cv2xRadio->onReady().get();
    }
    std::cerr << "[test] radio ready!" << std::endl;

    /* Create SPS flow — exactly like snaptel sample */
    SpsFlowInfo spsInfo;
    spsInfo.priority = Priority::PRIORITY_2;
    spsInfo.periodicity = Periodicity::PERIODICITY_100MS;
    spsInfo.nbytesReserved = 128;

    std::shared_ptr<ICv2xTxFlow> txFlow;
    {
        std::promise<ErrorCode> p;
        auto f = p.get_future();
        auto rc = cv2xRadio->createTxSpsFlow(
            TrafficIpType::TRAFFIC_NON_IP,
            1u,        /* serviceId */
            spsInfo,
            2500u,     /* srcPort */
            false,     /* no event flow */
            0,
            [&txFlow, &p](std::shared_ptr<ICv2xTxFlow> spsFlow,
                          std::shared_ptr<ICv2xTxFlow>,
                          ErrorCode spsErr, ErrorCode) {
                if (spsErr == ErrorCode::SUCCESS) txFlow = spsFlow;
                p.set_value(spsErr);
            });
        if (rc != Status::SUCCESS || f.get() != ErrorCode::SUCCESS) {
            std::cerr << "[test] createTxSpsFlow FAILED" << std::endl;
            return 1;
        }
    }

    std::cerr << "[test] TX flow created, sock=" << txFlow->getSock() << std::endl;

    /* Send 5 packets */
    char buf[128] = {};
    struct msghdr message = {};
    struct iovec iov[1] = {};
    char control[CMSG_SPACE(sizeof(int))];
    int priority = 3;

    iov[0].iov_base = buf;
    iov[0].iov_len = 128;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    auto *cmsghp = CMSG_FIRSTHDR(&message);
    cmsghp->cmsg_level = IPPROTO_IPV6;
    cmsghp->cmsg_type = IPV6_TCLASS;
    cmsghp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsghp), &priority, sizeof(int));

    for (int i = 0; i < 5; i++) {
        buf[0] = i;
        auto sent = sendmsg(txFlow->getSock(), &message, 0);
        std::cerr << "[test] sendmsg[" << i << "] = " << sent << std::endl;
        usleep(100000);
    }

    /* Close */
    {
        std::promise<ErrorCode> p;
        auto f = p.get_future();
        cv2xRadio->closeTxFlow(txFlow,
            [&p](std::shared_ptr<ICv2xTxFlow>, ErrorCode err) { p.set_value(err); });
        f.get();
    }

    std::cerr << "[test] Done!" << std::endl;
    return 0;
}
