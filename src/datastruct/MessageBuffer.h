#ifndef THREEPP_MESSAGEBUFFER_H
#define THREEPP_MESSAGEBUFFER_H

#include <cstdint>
#include <queue>
#include <string>
#include <memory>
#include <unordered_map>

#include "ReceivedMessage.h"

class MessageBuffer {
public:
    MessageBuffer(size_t max_size);

    int insert(ReceivedMessage& msg);

    bool contains(ReceivedMessage& msg);

    uint8_t getType(ReceivedMessage& msg);

    ReceivedMessage getMessage(std::string& msgHash);

private:
    size_t maxCapacity_;

    std::queue<std::string> FIFOBuffer_;

    std::unordered_map<std::string, ReceivedMessage> indexBuffer_;
};


#endif //THREEPP_MESSAGEBUFFER_H
