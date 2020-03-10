#include <iostream>
#include "MessageBuffer.h"
#include "../crypto/Utils.h"

MessageBuffer::MessageBuffer(size_t max_size) : max_size_(max_size) {}

std::shared_ptr<BufferedMessage> MessageBuffer::contains(NetworkMessage& msg) {
    std::vector<uint8_t> body_hash = utils::sha256(msg.body());

    for(auto it = message_buffer_.begin(); it != message_buffer_.end(); it++)
        if((*it)->msg_hash() == body_hash)
            return *it;

    return nullptr;
}

void MessageBuffer::add(ReceivedMessage& msg) {
    std::vector<uint8_t> body_hash = utils::sha256(msg.body());

    // Check if the message has already been received from a different sender
    for(auto it = message_buffer_.begin(); it != message_buffer_.end(); it++) {
        if ((*it)->msg_hash() == body_hash) {
            (*it)->sender_list().push_back(msg.connectionID());
            return;
        }
    }
    if(message_buffer_.size() == max_size_)
        message_buffer_.pop_front();

    BufferedMessage buff_msg(msg);
    message_buffer_.push_back(std::make_shared<BufferedMessage>(buff_msg));
}