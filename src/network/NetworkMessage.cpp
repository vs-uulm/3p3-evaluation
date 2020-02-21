#include <deque>
#include "NetworkMessage.h"

NetworkMessage::NetworkMessage()
: body_(nullptr) {}

NetworkMessage::NetworkMessage(uint32_t header, std::unique_ptr<uint8_t> body)
: body_(std::move(body)) {}

int NetworkMessage::add_body(std::unique_ptr<uint8_t> body) {
    if(body_)
        return -1;

    body_ = std::move(body);
    return 0;
}

uint8_t* NetworkMessage::get_header() {
    return header_;
}

uint8_t* NetworkMessage::get_body() {
    return body_.get();
}