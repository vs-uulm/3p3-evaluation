#ifndef THREEPP_INITSTATE_H
#define THREEPP_INITSTATE_H

#include "../threePP/DCNetwork.h"
#include "DCState.h"

class InitState : public DCState {
public:
    InitState();

    virtual ~InitState();

    virtual std::unique_ptr<DCState> executeTask(DCNetwork& DCNet);
};


#endif //THREEPP_INITSTATE_H
