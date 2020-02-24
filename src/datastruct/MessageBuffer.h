#ifndef THREEPP_MESSAGEBUFFER_H
#define THREEPP_MESSAGEBUFFER_H

#include <cstdint>
#include <list>
#include <memory>

#include "../network/Peer.h"
#include "../threePP/ProtocolPhase.h"

struct BufferedMessage {
    ProtocolPhase phase;
    uint8_t msg_hash[32];
    std::list<std::shared_ptr<Peer>> senders;
};

class MessageBuffer {

};


#endif //THREEPP_MESSAGEBUFFER_H
