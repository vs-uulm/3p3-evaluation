#include "BufferedMessage.h"

#include <algorithm>

BufferedMessage::BufferedMessage(NetworkMessage& msg, uint32_t connectionID) {
    senderList_.insert(connectionID);
}

void BufferedMessage::addSender(uint32_t connectionID) {
    if(senderList_.find(connectionID) == senderList_.end())
        senderList_.insert(connectionID);
}

bool BufferedMessage::receivedBy(uint32_t connectionID) {
    if(senderList_.find(connectionID) != senderList_.end())
        return true;
    return false;
}

