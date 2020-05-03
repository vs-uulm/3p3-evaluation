#ifndef THREEPP_MESSAGEBUFFER_H
#define THREEPP_MESSAGEBUFFER_H

#include <cstdint>
#include <queue>
#include <string>
#include <memory>
#include <unordered_map>

#include "BufferedMessage.h"

class MessageBuffer {
public:
    MessageBuffer(size_t max_size);

    void insert(ReceivedMessage& msg);

    bool contains(ReceivedMessage& msg);

    uint8_t getType(ReceivedMessage& msg);

private:
    size_t maxCapacity_;

    std::queue<std::string> FIFOBuffer_;

    std::unordered_map<std::string, uint8_t> indexBuffer_;
};


#endif //THREEPP_MESSAGEBUFFER_H
