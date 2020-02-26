#include "ReceivedMessage.h"

ReceivedMessage::ReceivedMessage(uint32_t sender_ID) : sender_ID_(sender_ID) {}

void ReceivedMessage::resize_body() {
    uint32_t body_size = (header_[1] << 16) | (header_[2] << 8) | header_[3];
    body_.resize(body_size);
}

uint32_t ReceivedMessage::sender_ID() {
    return sender_ID_;
}