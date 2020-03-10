#ifndef THREEPP_PEER_H
#define THREEPP_PEER_H

#include "P2PConnection.h"

class Peer {
public:
    Peer(uint32_t nodeID);
    uint32_t nodeID();
    int sendMsg(NetworkMessage msg);

private:
    uint32_t nodeID_;
};


#endif //THREEPP_PEER_H
