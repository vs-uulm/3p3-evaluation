#ifndef THREEPP_MESSAGEQUEUE_H
#define THREEPP_MESSAGEQUEUE_H

#include <cstdint>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <iostream>


template<class T>
class MessageQueue {
public:
    void push(T msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        msg_queue_.push(msg);
        // notify the consumer thread
        cond_var_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_var_.wait(lock, [&](){
            // deal with a spurious wakeup
            return !msg_queue_.empty();
        });

        T msg = msg_queue_.front();
        msg_queue_.pop();
        lock.unlock();
        return msg;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return msg_queue_.empty();
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(mutex_);
        return msg_queue_.size();
    }

private:
    std::mutex mutex_;

    std::condition_variable cond_var_;

    std::queue<T> msg_queue_;
};

#endif //THREEPP_MESSAGEQUEUE_H
