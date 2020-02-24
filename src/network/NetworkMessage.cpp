#include <deque>

#include "NetworkMessage.h"

NetworkMessage::NetworkMessage(uint8_t msg_type, uint32_t body_len, std::unique_ptr<uint8_t> body)
: body_(std::move(body)), body_len_(body_len) {
    if(body_len > 0xFFFFFF)
        throw std::invalid_argument("Body length is limited to 24 Bits");
    header_[0] = msg_type;
    header_[1] = (body_len & 0xFF0000) >> 16;
    header_[2] = (body_len & 0x00FF00) >> 8;
    header_[3] = (body_len & 0x0000FF);
}

uint8_t* NetworkMessage::header() {
    return header_;
}

uint8_t* NetworkMessage::body() {
    return body_.get();
}

uint32_t NetworkMessage::body_len() {
    return body_len_;
}