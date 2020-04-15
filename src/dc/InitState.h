#ifndef THREEPP_INITSTATE_H
#define THREEPP_INITSTATE_H

#include "DCNetwork.h"
#include "DCState.h"

class InitState : public DCState {
public:
    InitState(DCNetwork& DCNet);

    virtual ~InitState();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;
};

#endif //THREEPP_INITSTATE_H
