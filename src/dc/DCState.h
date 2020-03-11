#ifndef THREEPP_DCSTATE_H
#define THREEPP_DCSTATE_H

#include <memory>

class DCNetwork;

class DCState {
public:
    virtual ~DCState() {}

    virtual std::unique_ptr<DCState> executeTask(DCNetwork& DCNet) = 0;
};

#endif //THREEPP_DCSTATE_H
