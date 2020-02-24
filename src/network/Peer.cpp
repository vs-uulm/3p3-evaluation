#include "Peer.h"

/*
 * Peer(std::shared_ptr<Node> node_);
   Peer(std::shared_ptr<Node> node_, std::shared_ptr<P2PConnection> connection_);
 *
*/

Peer::Peer(Node& node_) : Node(node_) {

}
