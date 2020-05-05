#ifndef THREEPP_VIRTUALSOURCE_H
#define THREEPP_VIRTUALSOURCE_H

#include <cstdint>
#include <vector>

class VirtualSource {
public:
    VirtualSource(std::vector<uint32_t>& neighbors, std::vector<uint8_t> message);

    VirtualSource(std::vector<uint32_t>& neighbors, std::vector<uint8_t> message, std::vector<uint8_t> VSToken);

    void forwardMessage();

private:
    uint16_t s;

    uint16_t h;

    uint32_t v_prev;

    std::vector<uint8_t> r;

    std::vector<uint8_t> message_;

    std::vector<uint32_t>& neighbors_;
};


#endif //THREEPP_VIRTUALSOURCE_H
