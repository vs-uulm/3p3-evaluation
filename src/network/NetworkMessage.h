#ifndef THREEPP_NETWORKMESSAGE_H
#define THREEPP_NETWORKMESSAGE_H

#include <memory>
#include <vector>

class NetworkMessage {
public:
    NetworkMessage();

    NetworkMessage(uint8_t msg_type, std::vector<uint8_t>& body);

    std::vector<uint8_t>& header();

    std::vector<uint8_t>& body();

protected:
    std::vector<uint8_t> header_;
    std::vector<uint8_t> body_;
};


#endif //THREEPP_NETWORKMESSAGE_H
