#ifndef THREEPP_BUFFEREDMESSAGE_H
#define THREEPP_BUFFEREDMESSAGE_H

#include <list>
#include <cstdint>
#include <vector>
#include <set>
#include "ReceivedMessage.h"

class BufferedMessage {
public:
    BufferedMessage(NetworkMessage& msg, uint32_t connectionID);

    void addSender(uint32_t connectionID);

    bool receivedBy(uint32_t connectionID);

private:
    std::set<uint32_t> senderList_;
};


#endif //THREEPP_BUFFEREDMESSAGE_H
