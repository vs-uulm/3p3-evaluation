#ifndef THREEPP_INIT_H
#define THREEPP_INIT_H

#include "../threePP/DCNetwork.h"
#include "DCState.h"

class Init : public DCState {
public:
    Init();

    virtual ~Init();

    virtual std::unique_ptr<DCState> executeTask(DCNetwork& DCNet);
};

#endif //THREEPP_INIT_H
