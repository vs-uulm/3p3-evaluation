#include "ReceivedMessage.h"

ReceivedMessage::ReceivedMessage() : connectionID_(0) {}

ReceivedMessage::ReceivedMessage(uint32_t connectionID) : connectionID_(connectionID) {}

void ReceivedMessage::resizeBody() {
    uint32_t body_size = (header_[1] << 16) | (header_[2] << 8) | header_[3];
    body_.resize(body_size);
}

ReceivedMessage::ReceivedMessage(uint32_t connectionID, uint8_t msgType, uint32_t senderID, std::vector<uint8_t> body)
: NetworkMessage(msgType, senderID, std::move(body)), connectionID_(connectionID) {}

uint8_t ReceivedMessage::msgType() {
    return header_[0];
}

uint32_t ReceivedMessage::connectionID() {
    return connectionID_;
}