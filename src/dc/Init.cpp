#include <iostream>
#include <thread>
#include "Init.h"
#include "Ready.h"
#include "../datastruct/MessageType.h"

std::mutex c_mutex;

Init::Init() {}

Init::~Init() {}

std::unique_ptr<DCState> Init::executeTask(DCNetwork &DCNet) {
    while (DCNet.members().size() < DCNet.k() - 1) {
        auto receivedMessage = DCNet.inbox().pop();

        // filter early ready messages
        while((receivedMessage->msgType() != HelloMessage) && (receivedMessage->msgType() != HelloResponse)) {
            DCNet.inbox().push(receivedMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            receivedMessage = DCNet.inbox().pop();
        }
            uint32_t nodeID = *(receivedMessage->body().data());
            {
                std::lock_guard<std::mutex> lock(c_mutex);
                //std::cout << "Received hello message from Instance: " << nodeID
                //          << " through connection: " << receivedMessage->connectionID() << std::endl;
            }
            DCNet.members().insert(std::make_pair(nodeID, receivedMessage->connectionID()));
    }
    // perform a state transition
    return std::make_unique<Ready>();
}