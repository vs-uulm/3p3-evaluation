#ifndef THREEPP_INIT_H
#define THREEPP_INIT_H

#include "DCNetwork.h"
#include "DCState.h"

class Init : public DCState {
public:
    Init(DCNetwork& DCNet);

    virtual ~Init();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;
};

#endif //THREEPP_INIT_H
