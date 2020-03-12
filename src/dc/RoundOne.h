#ifndef THREEPP_ROUNDONE_H
#define THREEPP_ROUNDONE_H

#include "DCState.h"

class RoundOne : public DCState {
public:
    RoundOne();

    virtual ~RoundOne();

    virtual std::unique_ptr<DCState> executeTask(DCNetwork& DCNet);
};


#endif //THREEPP_ROUNDONE_H
