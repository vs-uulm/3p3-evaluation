#include <deque>
#include <iterator>
#include "NetworkMessage.h"

NetworkMessage::NetworkMessage() : payload_(nullptr) {}

NetworkMessage::NetworkMessage(int msg_type, uint16_t msg_len, uint8_t* payload)
: msg_type_(msg_type), msg_len_(msg_len) {
    payload_ = new uint8_t[msg_len];
    std::copy(payload, payload + msg_len, payload_);
}

NetworkMessage::~NetworkMessage(){
    if(payload_)
        delete payload_;
}