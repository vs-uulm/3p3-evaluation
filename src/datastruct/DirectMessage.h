#ifndef THREEPP_DIRECTMESSAGE_H
#define THREEPP_DIRECTMESSAGE_H

#include "NetworkMessage.h"

class DirectMessage : public NetworkMessage {
public:
    DirectMessage(uint32_t receiverID, uint8_t msg_type, std::vector<uint8_t>& body);

    uint32_t receiverID();

private:
    uint32_t receiverID_;
};


#endif //THREEPP_DIRECTMESSAGE_H
