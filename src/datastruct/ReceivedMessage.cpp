#include "ReceivedMessage.h"

ReceivedMessage::ReceivedMessage(uint32_t connectionID) : connectionID_(connectionID) {}

void ReceivedMessage::resizeBody() {
    uint32_t body_size = (header_[1] << 16) | (header_[2] << 8) | header_[3];
    body_.resize(body_size);
}

uint8_t ReceivedMessage::msgType() {
    return header_[0];
}

uint32_t ReceivedMessage::connectionID() {
    return connectionID_;
}