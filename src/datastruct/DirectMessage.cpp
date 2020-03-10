#include "DirectMessage.h"

DirectMessage::DirectMessage(uint32_t receiverID, uint8_t msg_type, std::vector<uint8_t>& body)
: NetworkMessage(msg_type, body), receiverID_(receiverID) {}

uint32_t DirectMessage::receiverID() {
    return receiverID_;
}