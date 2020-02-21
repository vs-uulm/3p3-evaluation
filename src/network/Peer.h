#ifndef THREEPP_PEER_H
#define THREEPP_PEER_H

#include "Node.h"
#include "P2PConnection.h"

#include <openssl/evp.h>

class Peer : public Node {
public:
    Peer(std::shared_ptr<Node> node_);
    Peer(std::shared_ptr<Node> node_, std::shared_ptr<P2PConnection> connection_);

private:
    EVP_PKEY* public_key;
    std::shared_ptr<P2PConnection> connection;
};


#endif //THREEPP_PEER_H
