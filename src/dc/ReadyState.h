#ifndef THREEPP_READYSTATE_H
#define THREEPP_READYSTATE_H

#include "DCNetwork.h"
#include "DCState.h"

class ReadyState : public DCState {
public:
    ReadyState(DCNetwork& DCNet);

    virtual ~ReadyState();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;
};

#endif //THREEPP_READYSTATE_H
