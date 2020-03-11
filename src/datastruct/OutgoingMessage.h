#ifndef THREEPP_OUTGOINGMESSAGE_H
#define THREEPP_OUTGOINGMESSAGE_H

#include <memory>
#include <vector>
#include "NetworkMessage.h"

class OutgoingMessage : public NetworkMessage {
public:
    OutgoingMessage();

    OutgoingMessage(int receiverID, uint8_t msg_type, std::vector<uint8_t>& body);

    int receiverID();

private:
    int receiverID_;
};


#endif //THREEPP_OUTGOINGMESSAGE_H
