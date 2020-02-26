#include "MessageQueue.h"

void MessageQueue::push(msg_ptr msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    msg_queue_.push(msg);
    // notify the consumer thread
    cond_var_.notify_one();
}

msg_ptr MessageQueue::pop() {
    std::unique_lock<std::mutex> lock(mutex_);
    cond_var_.wait(lock, [&](){
        // deal with spurious wakeup
        return !msg_queue_.empty();
    });
    msg_ptr msg = msg_queue_.front();
    msg_queue_.pop();
    lock.unlock();
    return msg;
}