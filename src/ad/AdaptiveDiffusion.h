#ifndef THREEPP_ADAPTIVEDIFFUSION_H
#define THREEPP_ADAPTIVEDIFFUSION_H

#include <cstdint>
#include <cmath>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/OutgoingMessage.h"

namespace AdaptiveDiffusion {
    uint32_t Eta = 2;
    uint32_t d = 4;

    double p(uint32_t s, uint32_t h) {
        if(Eta == 2)
            return (s-2*h+2)/(s+2);
        else
            return (std::pow(Eta-1, s/2.0-h+1)-1) / (std::pow(Eta-1, s/2.0+1)-1);
    }
};


#endif //THREEPP_ADAPTIVEDIFFUSION_H
