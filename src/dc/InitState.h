#ifndef THREEPP_INITSTATE_H
#define THREEPP_INITSTATE_H

#include "DCNetworkState.h"
#include "../threePP/DCNetwork.h"

class InitState : public DCNetworkState {
public:
    InitState();
    void executeTask();
private:
    //DCNetwork& DCNet_;
};


#endif //THREEPP_INITSTATE_H
