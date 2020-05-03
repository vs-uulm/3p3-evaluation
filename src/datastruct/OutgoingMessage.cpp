#include <deque>
#include <iostream>

#include "OutgoingMessage.h"

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID)
: NetworkMessage(msg_type, senderID), receiverID_(receiverID), receivedFrom_(SELF) {}

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID, std::vector<uint8_t> body)
: NetworkMessage(msg_type, senderID, std::move(body)), receiverID_(receiverID), receivedFrom_(SELF) {}

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID, uint32_t receivedFrom, std::vector<uint8_t> body)
: NetworkMessage(msg_type, senderID, std::move(body)), receiverID_(receiverID), receivedFrom_(receivedFrom) {}

uint32_t OutgoingMessage::receiverID() {
    return receiverID_;
}

uint32_t OutgoingMessage::receivedFrom() {
    return receivedFrom_;
}