#ifndef THREEPP_ROUNDTWO_H
#define THREEPP_ROUNDTWO_H

#include <array>
#include <vector>
#include "DCState.h"

class RoundTwo : public DCState {
public:
    RoundTwo(DCNetwork& DCNet, size_t p, std::vector<std::array<uint8_t, 32>>& K, std::vector<uint16_t>& L);

    virtual ~RoundTwo();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;

    size_t p_;

    std::vector<std::array<uint8_t, 32>> K;

    std::vector<uint16_t> L;
};


#endif //THREEPP_ROUNDTWO_H
