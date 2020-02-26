#ifndef THREEPP_RECEIVEDMESSAGE_H
#define THREEPP_RECEIVEDMESSAGE_H

#include "NetworkMessage.h"

class ReceivedMessage : public NetworkMessage {
public:
    ReceivedMessage(uint32_t sender_ID);

    void resize_body();

    uint32_t sender_ID();

private:
    uint32_t sender_ID_;

};


#endif //THREEPP_RECEIVEDMESSAGE_H
