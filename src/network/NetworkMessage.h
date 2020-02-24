#ifndef THREEPP_NETWORKMESSAGE_H
#define THREEPP_NETWORKMESSAGE_H

#include <memory>

class NetworkMessage {
public:
    NetworkMessage();

    NetworkMessage(uint8_t msg_type, uint32_t body_len, std::unique_ptr<uint8_t> body);

    uint8_t* header();

    uint8_t* body();

    uint32_t body_len();

private:
    uint8_t header_[4];
    uint32_t body_len_;
    std::unique_ptr<uint8_t> body_;
};


#endif //THREEPP_NETWORKMESSAGE_H
