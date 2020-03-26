#ifndef THREEPP_OUTGOINGMESSAGE_H
#define THREEPP_OUTGOINGMESSAGE_H

#include <memory>
#include <vector>
#include "NetworkMessage.h"

const uint32_t BROADCAST = 0xFFFFFFFF;

const uint32_t SELF      = 0xFFFFFFFD;

class OutgoingMessage : public NetworkMessage {
public:
    OutgoingMessage();

    OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID);

    OutgoingMessage(uint32_t receiverID, uint8_t msg_type, uint32_t senderID, std::vector<uint8_t>& body);

    uint32_t receiverID();

private:
    uint32_t receiverID_;
};


#endif //THREEPP_OUTGOINGMESSAGE_H
