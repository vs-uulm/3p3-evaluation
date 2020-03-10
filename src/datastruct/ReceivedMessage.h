#ifndef THREEPP_RECEIVEDMESSAGE_H
#define THREEPP_RECEIVEDMESSAGE_H

#include "NetworkMessage.h"

class ReceivedMessage : public NetworkMessage {
public:
    ReceivedMessage(uint32_t connectionID);

    void resizeBody();

    uint8_t msgType();

    uint32_t connectionID();

private:
    uint32_t connectionID_;

};


#endif //THREEPP_RECEIVEDMESSAGE_H
