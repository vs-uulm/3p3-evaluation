#ifndef THREEPP_READY_H
#define THREEPP_READY_H

#include "DCNetwork.h"
#include "DCState.h"

class Ready : public DCState {
public:
    Ready(DCNetwork& DCNet);

    virtual ~Ready();

    virtual std::unique_ptr<DCState> executeTask();

private:
    DCNetwork& DCNetwork_;
};

#endif //THREEPP_READY_H
