#include <iostream>
#include <thread>
#include "Init.h"
#include "Ready.h"
#include "../datastruct/MessageType.h"

std::mutex c_mutex;

Init::Init(DCNetwork& DCNet) : DCNetwork_(DCNet) {}

Init::~Init() {}

std::unique_ptr<DCState> Init::executeTask() {
    while (DCNetwork_.members().size() < DCNetwork_.k() - 1) {
        auto receivedMessage = DCNetwork_.inbox().pop();

        // filter early ready messages
        while((receivedMessage->msgType() != HelloMessage) && (receivedMessage->msgType() != HelloResponse)) {
            DCNetwork_.inbox().push(receivedMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            receivedMessage = DCNetwork_.inbox().pop();
        }
            uint32_t nodeID = *(receivedMessage->body().data());
            {
                std::lock_guard<std::mutex> lock(c_mutex);
                //std::cout << "Received hello message from Instance: " << nodeID
                //          << " through connection: " << receivedMessage->connectionID() << std::endl;
            }
            DCNetwork_.members().insert(std::make_pair(nodeID, receivedMessage->connectionID()));
    }
    // perform a state transition
    return std::make_unique<Ready>(DCNetwork_);
}