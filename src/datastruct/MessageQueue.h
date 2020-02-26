#ifndef THREEPP_MESSAGEQUEUE_H
#define THREEPP_MESSAGEQUEUE_H

#include <cstdint>
#include <queue>
#include <mutex>

#include "NetworkMessage.h"

typedef std::shared_ptr<NetworkMessage> msg_ptr;

class MessageQueue {
public:
    void push(msg_ptr);

    msg_ptr pop();

private:
    std::mutex mutex_;
    std::condition_variable cond_var_;
    std::queue<msg_ptr> msg_queue_;
};

#endif //THREEPP_MESSAGEQUEUE_H
