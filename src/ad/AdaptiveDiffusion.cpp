#include "AdaptiveDiffusion.h"

namespace AdaptiveDiffusion {
    size_t Eta = 3;
    size_t maxDepth = 10;
    size_t RTT = 150;

    double p(uint16_t s, uint16_t h) {
        if(Eta == 2)
            return (s-2*h+2)/(s+2.0);
        else
            return (std::pow(Eta-1, s/2.0-h+1)-1) / (std::pow(Eta-1, s/2.0+1)-1);
    }

    std::vector<uint8_t> generateVSToken(uint16_t s, uint16_t h, std::vector<uint8_t>& message) {
        std::vector<uint8_t> VSToken(36);

        // set s
        VSToken[0] = (s & 0xFF00) >> 8;
        VSToken[1] = (s & 0x00FF);

        // set h
        VSToken[2] = (h & 0xFF00) >> 8;
        VSToken[3] = (h & 0x00FF);

        std::string msgHash = utils::sha256(message);
        std::copy(msgHash.begin(), msgHash.end(), &VSToken[4]);

        return VSToken;
    }

    size_t maxRemainingSteps(uint16_t s) {
        size_t delta = maxDepth - s;

        if(delta > 4)
            return (std::pow(delta, 2) + delta) / 2.0 + 1;
        else
            return 3*delta - 1;
    }
};


