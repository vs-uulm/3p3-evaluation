#ifndef THREEPP_MESSAGEBUFFER_H
#define THREEPP_MESSAGEBUFFER_H

#include <cstdint>
#include <deque>
#include <memory>

#include "BufferedMessage.h"

class MessageBuffer {
public:
    MessageBuffer(size_t max_size);

    void add(ReceivedMessage& msg);

    std::shared_ptr<BufferedMessage> contains(NetworkMessage& msg);

private:
    size_t max_size_;

    std::deque<std::shared_ptr<BufferedMessage>> message_buffer_;
};


#endif //THREEPP_MESSAGEBUFFER_H
