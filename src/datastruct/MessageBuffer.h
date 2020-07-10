#ifndef THREEPP_MESSAGEBUFFER_H
#define THREEPP_MESSAGEBUFFER_H

#include <cstdint>
#include <queue>
#include <set>
#include <string>
#include <memory>
#include <unordered_map>

#include "ReceivedMessage.h"

class MessageBuffer {
public:
    MessageBuffer(size_t max_size);

    int insert(ReceivedMessage msg);

    int insert(ReceivedMessage msg, std::set<uint32_t> neighbors);

    bool contains(ReceivedMessage& msg);

    uint8_t getType(ReceivedMessage& msg);

    uint32_t getSenderID(ReceivedMessage& msg);

    std::set<uint32_t>& getSelectedNeighbors(ReceivedMessage& msg);

    ReceivedMessage getMessage(std::string& msgHash);

private:
    size_t maxCapacity_;

    std::set<uint32_t> emptySet_;

    std::queue<std::string> FIFOBuffer_;

    std::unordered_map<std::string, std::pair<ReceivedMessage, std::set<uint32_t>>> indexBuffer_;
};


#endif //THREEPP_MESSAGEBUFFER_H
