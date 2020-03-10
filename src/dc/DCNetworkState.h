#ifndef THREEPP_DCNETWORKSTATE_H
#define THREEPP_DCNETWORKSTATE_H

#include <memory>

class DCNetworkState {
public:
    //virtual ~DCNetworkState();
    virtual void executeTask() = 0;
};

#endif //THREEPP_DCNETWORKSTATE_H
