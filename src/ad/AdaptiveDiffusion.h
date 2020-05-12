#ifndef THREEPP_ADAPTIVEDIFFUSION_H
#define THREEPP_ADAPTIVEDIFFUSION_H

#include <cstdint>
#include <cmath>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/OutgoingMessage.h"
#include "../utils/Utils.h"

namespace AdaptiveDiffusion {
    double p(uint16_t s, uint16_t h);

    std::vector<uint8_t> generateVSToken(uint16_t s, uint16_t h, std::vector<uint8_t>& message);

    size_t maxRemainingSteps(uint16_t s);

    extern size_t Eta;
    extern size_t maxDepth;
    extern size_t RTT;
};


#endif //THREEPP_ADAPTIVEDIFFUSION_H
