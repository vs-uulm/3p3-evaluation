#include <iostream>
#include "NetworkMessage.h"

NetworkMessage::NetworkMessage() : header_{0} {}

NetworkMessage::NetworkMessage(uint8_t msgType) : header_{0} {
    header_[0] = msgType;
}

NetworkMessage::NetworkMessage(uint8_t msgType, uint32_t senderID) : header_{0} {
    header_[0] = msgType;

    header_[4] = (senderID & 0xFF000000) >> 24;
    header_[5] = (senderID & 0x00FF0000) >> 16;
    header_[6] = (senderID & 0x0000FF00) >> 8;
    header_[7] = (senderID & 0x000000FF);
}

NetworkMessage::NetworkMessage(uint8_t msgType, uint32_t senderID, std::vector<uint8_t> body)
: body_(body) {
    if(body.size() > 0x00FFFFFF)
        throw std::invalid_argument("Body length is limited to 2^24 Bytes");

    header_[0] = msgType;

    header_[1] = (body.size() & 0x00FF0000) >> 16;
    header_[2] = (body.size() & 0x0000FF00) >> 8;
    header_[3] = (body.size() & 0x000000FF);

    header_[4] = (senderID & 0xFF000000) >> 24;
    header_[5] = (senderID & 0x00FF0000) >> 16;
    header_[6] = (senderID & 0x0000FF00) >> 8;
    header_[7] = (senderID & 0x000000FF);
}

std::array<uint8_t, 8>& NetworkMessage::header() {
    return header_;
}

std::vector<uint8_t>& NetworkMessage::body() {
    return body_;
}

uint32_t NetworkMessage::senderID() {
    return (header_[4] << 24) | (header_[5] << 16) | (header_[6] << 8) | header_[7];
}