#ifndef THREEPP_READY_H
#define THREEPP_READY_H

#include "../threePP/DCNetwork.h"
#include "DCState.h"

class Ready : public DCState {
public:
    Ready();

    virtual ~Ready();

    virtual std::unique_ptr<DCState> executeTask(DCNetwork& DCNet);
};

#endif //THREEPP_READY_H
