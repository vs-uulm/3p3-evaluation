#include "MessageBuffer.h"
#include "../utils/Utils.h"

MessageBuffer::MessageBuffer(size_t maxCapacity) : maxCapacity_(maxCapacity) {}

bool MessageBuffer::contains(ReceivedMessage& msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end())
        return true;

    return false;
}

void MessageBuffer::insert(ReceivedMessage& msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end()) {
        indexBuffer_[msgHash] = msg.msgType();
    } else {
        if (FIFOBuffer_.size() == maxCapacity_) {
            indexBuffer_.erase(FIFOBuffer_.front());
            FIFOBuffer_.pop();
        }

        FIFOBuffer_.push(msgHash);

        indexBuffer_.insert(std::pair(msgHash, msg.msgType()));
    }
}

uint8_t MessageBuffer::getType(ReceivedMessage &msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end())
        return position->second;

    return 0xFF;
}