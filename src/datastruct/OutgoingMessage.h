#ifndef THREEPP_OUTGOINGMESSAGE_H
#define THREEPP_OUTGOINGMESSAGE_H

#include <memory>
#include <vector>
#include "NetworkMessage.h"

const uint32_t BROADCAST = 0xFFFFFFFF;
// TODO implement the handler
const uint32_t DC_NET    = 0xFFFFFFFE;

const uint32_t SELF      = 0xFFFFFFFD;

class OutgoingMessage : public NetworkMessage {
public:
    OutgoingMessage();

    OutgoingMessage(uint32_t receiverID, uint8_t msg_type);

    OutgoingMessage(uint32_t receiverID, uint8_t msg_type, std::vector<uint8_t>& body);

    uint32_t receiverID();

private:
    uint32_t receiverID_;
};


#endif //THREEPP_OUTGOINGMESSAGE_H
