#ifndef THREEPP_NETWORKMESSAGE_H
#define THREEPP_NETWORKMESSAGE_H

#include <vector>
#include <array>

const uint32_t BROADCAST  = 0xFFFFFFFF;

const uint32_t SELF       = 0xFFFFFFFE;

const uint32_t CENTRAL    = 0xFFFFFFFD;

class NetworkMessage {
public:
    NetworkMessage();

    NetworkMessage(uint8_t msgType);

    NetworkMessage(uint8_t msgType, uint32_t senderID);

    NetworkMessage(uint8_t msgType, uint32_t senderID, std::vector<uint8_t> body);

    std::array<uint8_t, 8>& header();

    std::vector<uint8_t>& body();

    uint32_t senderID();

protected:
    std::array<uint8_t, 8> header_;

    std::vector<uint8_t> body_;
};

#endif //THREEPP_NETWORKMESSAGE_H
