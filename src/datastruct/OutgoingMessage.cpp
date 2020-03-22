#include <deque>
#include <iostream>

#include "OutgoingMessage.h"

OutgoingMessage::OutgoingMessage()  {}

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID)
: NetworkMessage(msg_type, senderID), receiverID_(receiverID) {}

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID, std::vector<uint8_t>& body)
: NetworkMessage(msg_type, senderID, body), receiverID_(receiverID) {}

uint32_t OutgoingMessage::receiverID() {
    return receiverID_;
}