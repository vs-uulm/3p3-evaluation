#ifndef THREEPP_READYSTATE_H
#define THREEPP_READYSTATE_H

#include "DCNetworkState.h"
#include "../threePP/DCNetwork.h"

class ReadyState : public DCNetworkState {
public:
    ReadyState(DCNetwork& DCNet);
    void executeTask();
private:
    DCNetwork& DCNet_;
};

#endif //THREEPP_READYSTATE_H
