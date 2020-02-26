#include "MessageQueue.h"

void MessageQueue::push(msg_ptr msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    msg_queue_.push(msg);
}

msg_ptr MessageQueue::pop() {
    msg_ptr msg;
    if(!msg_queue_.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        msg = msg_queue_.front();
        msg_queue_.pop();
    }
    return msg;
}