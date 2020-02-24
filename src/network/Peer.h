#ifndef THREEPP_PEER_H
#define THREEPP_PEER_H

#include "Node.h"
#include "P2PConnection.h"

#include <openssl/evp.h>

class Peer : public Node {
public:
    Peer(Node& node_);

private:
    EVP_PKEY* public_key;
};


#endif //THREEPP_PEER_H
