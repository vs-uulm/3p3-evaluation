#include <iostream>
#include "RoundTwo.h"
#include "Init.h"

RoundTwo::RoundTwo(DCNetwork &DCNet, size_t p, std::vector<std::array<uint8_t, 32>>& K, std::vector<uint16_t>& L)
: DCNetwork_(DCNet), p_(p), K(std::move(K)), L(std::move(L)) {
}

RoundTwo::~RoundTwo() {

}

std::unique_ptr<DCState> RoundTwo::executeTask() {
    std::vector<uint8_t> submittedMessage;

    uint16_t l = 0;
    if(p_ > -1) {
        submittedMessage = DCNetwork_.submittedMessages().front();
        DCNetwork_.submittedMessages().pop();

        // ensure that the message size does not exceed 2^16 Bytes
        l = submittedMessage.size() > USHRT_MAX ? USHRT_MAX : submittedMessage.size();
    }


    return std::make_unique<Init>(DCNetwork_);
}