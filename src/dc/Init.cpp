#include <iostream>
#include <thread>
#include "Init.h"
#include "Ready.h"
#include "../datastruct/MessageType.h"

Init::Init(DCNetwork& DCNet) : DCNetwork_(DCNet) {
}

Init::~Init() {}

std::unique_ptr<DCState> Init::executeTask() {
    while (DCNetwork_.members().size() < DCNetwork_.k()) {
        auto receivedMessage = DCNetwork_.inbox().pop();

        // skip early arriving ready messages
        while((receivedMessage.msgType() != HelloMessage) && (receivedMessage.msgType() != HelloResponse)) {
            DCNetwork_.inbox().push(receivedMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            receivedMessage = DCNetwork_.inbox().pop();
        }

        uint32_t nodeID = receivedMessage.senderID();
        DCMember member(nodeID, receivedMessage.connectionID(), DCNetwork_.neighbors()[nodeID].publicKey());
        DCNetwork_.members().insert(std::make_pair(receivedMessage.senderID(), member));
    }
    // perform a state transition
    return std::make_unique<Ready>(DCNetwork_);
}