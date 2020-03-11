#ifndef THREEPP_READYSTATE_H
#define THREEPP_READYSTATE_H

#include "../threePP/DCNetwork.h"
#include "DCState.h"

class ReadyState : public DCState {
public:
    ReadyState();

    virtual ~ReadyState();

    virtual std::unique_ptr<DCState> executeTask(DCNetwork& DCNet);
};

#endif //THREEPP_READYSTATE_H
