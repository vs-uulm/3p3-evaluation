#ifndef THREEPP_RECEIVEDMESSAGE_H
#define THREEPP_RECEIVEDMESSAGE_H

#include "NetworkMessage.h"
#include <chrono>

typedef std::chrono::system_clock::time_point Timestamp;

class ReceivedMessage : public NetworkMessage {
public:
    ReceivedMessage();
    
    ReceivedMessage(uint32_t connectionID);

    ReceivedMessage(uint8_t msgType);

    ReceivedMessage(uint32_t connectionID, uint8_t msgType, uint32_t senderID, std::vector<uint8_t> body);

    void resizeBody();

    uint8_t msgType();

    uint32_t connectionID();

    void timestamp(Timestamp timestamp);

    Timestamp timestamp();

    void updateMsgType(uint8_t msgType);
private:
    uint32_t connectionID_;

    Timestamp timestamp_;
};


#endif //THREEPP_RECEIVEDMESSAGE_H
