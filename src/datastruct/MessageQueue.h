#ifndef THREEPP_MESSAGEQUEUE_H
#define THREEPP_MESSAGEQUEUE_H

#include <cstdint>
#include <queue>
#include <mutex>
#include <condition_variable>


template<class T>
class MessageQueue {
public:
    void push(std::shared_ptr<T> msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        msg_queue_.push(msg);
        // notify the consumer thread
        cond_var_.notify_one();
    }

    std::shared_ptr<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_var_.wait(lock, [&](){
            // deal with spurious wakeup
            return !msg_queue_.empty();
        });
        std::shared_ptr<T> msg = std::move(msg_queue_.front());
        msg_queue_.pop();
        lock.unlock();
        return msg;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return msg_queue_.empty();
    }

private:
    std::mutex mutex_;
    std::condition_variable cond_var_;
    std::queue<std::shared_ptr<T>> msg_queue_;
};

#endif //THREEPP_MESSAGEQUEUE_H
