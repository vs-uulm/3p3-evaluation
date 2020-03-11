#include <iostream>
#include "NetworkMessage.h"

NetworkMessage::NetworkMessage() : header_{0} {}

NetworkMessage::NetworkMessage(uint8_t msg_type, std::vector<uint8_t>& body) : header_{0}, body_(body) {
    if(body.size() > 0x00FFFFFF)
        throw std::invalid_argument("Body length is limited to 24 Bits");

    header_[0] = msg_type;
    header_[1] = (body.size() & 0x00FF0000) >> 16;
    header_[2] = (body.size() & 0x0000FF00) >> 8;
    header_[3] = (body.size() & 0x000000FF);
}

std::array<uint8_t, 4>& NetworkMessage::header() {
    return header_;
}

std::vector<uint8_t>& NetworkMessage::body() {
    return body_;
}