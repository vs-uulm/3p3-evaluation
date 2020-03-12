#include <deque>
#include <iostream>

#include "OutgoingMessage.h"

OutgoingMessage::OutgoingMessage()  {}

OutgoingMessage::OutgoingMessage(int receiverID, uint8_t msg_type)
: NetworkMessage(msg_type), receiverID_(receiverID) {}

OutgoingMessage::OutgoingMessage(int receiverID, uint8_t msg_type, std::vector<uint8_t>& body)
: NetworkMessage(msg_type, body), receiverID_(receiverID) {}

int OutgoingMessage::receiverID() {
    return receiverID_;
}