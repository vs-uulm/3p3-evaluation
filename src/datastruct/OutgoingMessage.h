#ifndef THREEPP_OUTGOINGMESSAGE_H
#define THREEPP_OUTGOINGMESSAGE_H

#include <memory>
#include <vector>
#include "NetworkMessage.h"

class OutgoingMessage : public NetworkMessage {
public:
    OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID);

    OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID, std::vector<uint8_t> body);

    // BROADCAST message
    OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID, uint32_t receivedFrom, std::vector<uint8_t> body);

    uint32_t receiverID();

    uint32_t receivedFrom();

private:
    uint32_t receiverID_;

    uint32_t receivedFrom_;
};


#endif //THREEPP_OUTGOINGMESSAGE_H
