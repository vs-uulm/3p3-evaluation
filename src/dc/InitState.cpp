#include <iostream>
#include "InitState.h"
#include "ReadyState.h"

std::mutex c_mutex;

InitState::InitState() {
    std::cout << "InitState Constructor" << std::endl;
}

InitState::~InitState() {
    std::cout << "InitState Destructor" << std::endl;
}

std::unique_ptr<DCState> InitState::executeTask(DCNetwork& DCNet) {
    while(DCNet.members().size() < DCNet.k()-1) {
        auto receivedMessage = DCNet.inbox().pop();
        uint32_t nodeID = *(receivedMessage->body().data());
        {
            std::lock_guard<std::mutex> lock(c_mutex);
            std::cout << "Received hello message from Instance: " << nodeID
                      << " through connection: " << receivedMessage->connectionID() << std::endl;
        }
        DCNet.members().insert(std::make_pair(nodeID, receivedMessage->connectionID()));
    }
    // transition
    return std::make_unique<ReadyState>();
}