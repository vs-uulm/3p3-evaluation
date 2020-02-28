#ifndef THREEPP_BUFFEREDMESSAGE_H
#define THREEPP_BUFFEREDMESSAGE_H

#include <list>
#include <cstdint>
#include <vector>
#include "ReceivedMessage.h"

class BufferedMessage {
public:
    BufferedMessage(ReceivedMessage& msg);

    void add_sender(uint32_t senderID);

    const std::vector<uint8_t>& msg_hash() const;

    std::list<uint32_t>& sender_list();

private:
    std::vector<uint8_t> msg_hash_;

    std::list<uint32_t> sender_list_;
};


#endif //THREEPP_BUFFEREDMESSAGE_H
