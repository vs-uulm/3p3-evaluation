#include <iostream>
#include "Init.h"
#include "Ready.h"

std::mutex c_mutex;

Init::Init() {}

Init::~Init() {}

std::unique_ptr<DCState> Init::executeTask(DCNetwork& DCNet) {
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

    // perform a state transition
    return std::make_unique<Ready>();
}