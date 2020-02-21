#ifndef THREEPP_NETWORKMESSAGE_H
#define THREEPP_NETWORKMESSAGE_H

#include <memory>

class NetworkMessage {
public:
    NetworkMessage();
    NetworkMessage(uint32_t header, std::unique_ptr<uint8_t> body);

    int add_body(std::unique_ptr<uint8_t> body);
    uint8_t* get_header();
    uint8_t* get_body();

private:
    uint8_t header_[4];
    std::unique_ptr<uint8_t> body_;
};


#endif //THREEPP_NETWORKMESSAGE_H
