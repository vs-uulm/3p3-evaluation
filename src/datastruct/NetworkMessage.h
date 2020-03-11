#ifndef THREEPP_NETWORKMESSAGE_H
#define THREEPP_NETWORKMESSAGE_H

#include <vector>
#include <array>

class NetworkMessage {
public:
    NetworkMessage();

    NetworkMessage(uint8_t msg_type, std::vector<uint8_t>& body);

    std::array<uint8_t, 4>& header();

    std::vector<uint8_t>& body();

protected:
    std::array<uint8_t, 4> header_;

    std::vector<uint8_t> body_;
};

#endif //THREEPP_NETWORKMESSAGE_H
