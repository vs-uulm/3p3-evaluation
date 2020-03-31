#include "BufferedMessage.h"
#include "../utils/Utils.h"

#include <algorithm>

BufferedMessage::BufferedMessage(ReceivedMessage& msg) : msg_hash_(utils::sha256(msg.body())) {
    sender_list_.push_back(msg.connectionID());
}

void BufferedMessage::add_sender(uint32_t senderID) {
    // check if the sender is already included in the list
    auto position = std::find(sender_list_.begin(), sender_list_.end(), senderID);
    if(position == sender_list_.end())
        sender_list_.push_back(senderID);
}

const std::vector<uint8_t>& BufferedMessage::msg_hash() const {
    return msg_hash_;
}

std::list<uint32_t> & BufferedMessage::sender_list() {
    return sender_list_;
}

