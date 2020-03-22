#ifndef THREEPP_ROUNDTWO_H
#define THREEPP_ROUNDTWO_H


#include "DCState.h"

class RoundTwo : public DCState {
public:
    RoundTwo(DCNetwork& DCNet);

    virtual ~RoundTwo();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;
};


#endif //THREEPP_ROUNDTWO_H
