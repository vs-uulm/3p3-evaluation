#include "RoundTwo.h"
#include "Init.h"

RoundTwo::RoundTwo(DCNetwork &DCNet) : DCNetwork_(DCNet) {

}

RoundTwo::~RoundTwo() {

}

std::unique_ptr<DCState> RoundTwo::executeTask() {
    // TODO

    return std::make_unique<Init>(DCNetwork_);
}