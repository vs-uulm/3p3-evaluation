#include <deque>
#include <iostream>

#include "OutgoingMessage.h"

OutgoingMessage::OutgoingMessage()  {}

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type)
: NetworkMessage(msg_type), receiverID_(receiverID) {}

OutgoingMessage::OutgoingMessage(uint32_t receiverID, uint8_t msg_type, std::vector<uint8_t>& body)
: NetworkMessage(msg_type, body), receiverID_(receiverID) {}

uint32_t OutgoingMessage::receiverID() {
    return receiverID_;
}