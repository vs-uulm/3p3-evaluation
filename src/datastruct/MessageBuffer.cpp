#include "MessageBuffer.h"
#include "MessageType.h"
#include "../utils/Utils.h"

MessageBuffer::MessageBuffer(size_t maxCapacity) : maxCapacity_(maxCapacity) {}

bool MessageBuffer::contains(ReceivedMessage& msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end())
        return true;

    return false;
}

// Flood and Prune insert
int MessageBuffer::insert(ReceivedMessage msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position == indexBuffer_.end()) {
        if (FIFOBuffer_.size() == maxCapacity_) {
            indexBuffer_.erase(FIFOBuffer_.front());
            FIFOBuffer_.pop();
        }

        FIFOBuffer_.push(msgHash);
        indexBuffer_.insert(std::pair(msgHash, std::pair(msg, std::set<uint32_t>())));
    } else if(position->second.first.msgType() == AdaptiveDiffusionMessage) {
        // update the message type
        position->second.first.updateMsgType(FloodAndPrune);
    }
    return 0;
}

// Adaptive Diffusion insert
int MessageBuffer::insert(ReceivedMessage msg, std::set<uint32_t> neighbors) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position == indexBuffer_.end()) {
        if (FIFOBuffer_.size() == maxCapacity_) {
            indexBuffer_.erase(FIFOBuffer_.front());
            FIFOBuffer_.pop();
        }

        FIFOBuffer_.push(msgHash);
        indexBuffer_.insert(std::pair(msgHash, std::pair(msg, neighbors)));
    }
    return 0;
}

uint8_t MessageBuffer::getType(ReceivedMessage& msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end())
        return position->second.first.msgType();

    return 0xFF;
}

uint32_t MessageBuffer::getSenderID(ReceivedMessage &msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end())
        return position->second.first.senderID();

    return 0xFFFFFFFB;
}

std::set<uint32_t> & MessageBuffer::getSelectedNeighbors(ReceivedMessage &msg) {
    std::string msgHash = utils::sha256(msg.body());

    auto position = indexBuffer_.find(msgHash);
    if(position != indexBuffer_.end())
        return position->second.second;

    return emptySet_;
}

ReceivedMessage MessageBuffer::getMessage(std::string& msgHash) {
    return indexBuffer_[msgHash].first;
}
