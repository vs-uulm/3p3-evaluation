#include <iostream>
#include <thread>
#include "DCNetwork.h"
#include "InitState.h"
#include "ReadyState.h"
#include "../datastruct/MessageType.h"
#include "SecuredInitialRound.h"
#include "UnsecuredInitialRound.h"

InitState::InitState(DCNetwork& DCNet) : DCNetwork_(DCNet) {
    //std::cout << "Init State" << std::endl;
}

InitState::~InitState() {}

std::unique_ptr<DCState> InitState::executeTask() {
    while (DCNetwork_.members().size() < DCNetwork_.k()) {
        auto receivedMessage = DCNetwork_.inbox().pop();

        // skip early arriving ready messages
        while((receivedMessage.msgType() != HelloMessage) && (receivedMessage.msgType() != HelloResponse)) {
            DCNetwork_.inbox().push(receivedMessage);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            receivedMessage = DCNetwork_.inbox().pop();
        }

        uint32_t nodeID = receivedMessage.senderID();
        DCMember member(nodeID, receivedMessage.connectionID(), DCNetwork_.neighbors()[nodeID].publicKey());
        DCNetwork_.members().insert(std::make_pair(receivedMessage.senderID(), member));
    }
    // perform a state transition
    //return std::make_unique<ReadyState>(DCNetwork_);

    // perform a state transition
    if(DCNetwork_.securityLevel() == Secured || DCNetwork_.securityLevel() == ProofOfFairness)
        return std::make_unique<SecuredInitialRound>(DCNetwork_);
    else
        return std::make_unique<UnsecuredInitialRound>(DCNetwork_);
}