#ifndef THREEPP_ADAPTIVEDIFFUSION_H
#define THREEPP_ADAPTIVEDIFFUSION_H

#include <cstdint>
#include <cmath>
#include "../datastruct/MessageQueue.h"
#include "../datastruct/OutgoingMessage.h"
#include "../utils/Utils.h"

namespace AdaptiveDiffusion {
    extern bool floodAndPrune;
    extern size_t Eta;
    extern size_t maxDepth;
    extern size_t propagationDelay;
};


#endif //THREEPP_ADAPTIVEDIFFUSION_H
