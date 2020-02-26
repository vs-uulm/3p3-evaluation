#ifndef THREEPP_BUFFEREDMESSAGE_H
#define THREEPP_BUFFEREDMESSAGE_H


#include <list>
#include <cstdint>
#include <vector>

class BufferedMessage {
public:
    BufferedMessage(uint32_t senderID, std::vector<uint8_t>& body_hash);

    void add_sender(uint32_t senderID);

    std::vector<uint8_t> const msg_hash() const;

    std::list<uint32_t> const sender_list() const;

private:
    std::vector<uint8_t> body_hash_;

    std::list<uint32_t> sender_list_;
};


#endif //THREEPP_BUFFEREDMESSAGE_H
