#include <iostream>
#include "DCNetwork.h"
#include "ReadyState.h"
#include "SecuredInitialRound.h"
#include "../datastruct/MessageType.h"
#include "UnsecuredInitialRound.h"

#include <thread>
#include <chrono>


ReadyState::ReadyState(DCNetwork& DCNet) : DCNetwork_(DCNet) {}

ReadyState::~ReadyState() {}

std::unique_ptr<DCState> ReadyState::executeTask() {
    uint32_t minimumID = DCNetwork_.nodeID();
    // determine whether the local node has the smallest nodeID
    for(auto& member : DCNetwork_.members())
        if(member.first < minimumID)
            minimumID = member.first;
    // this node acts as the group manager
    if(minimumID == DCNetwork_.nodeID()) {
        size_t memberCount = DCNetwork_.members().size();
        std::vector<uint32_t> readyNodes;
        readyNodes.reserve(memberCount);

        while(readyNodes.size() < memberCount - 1) {
            auto readyMessage = DCNetwork_.inbox().pop();
            if(readyMessage.msgType() != ReadyMessage) {
                std::cout << "Ready State:  inappropriate message received: " << (int) readyMessage.msgType() << std::endl;
                DCNetwork_.inbox().push(readyMessage);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                readyMessage = DCNetwork_.inbox().pop();
            }
            else {
                auto position = std::find(readyNodes.begin(), readyNodes.end(), readyMessage.connectionID());
                if(position == readyNodes.end())
                    readyNodes.push_back(readyMessage.connectionID());
            }
        }
        // the loop is terminated when all members of the DC network are ready
        OutgoingMessage startDCRound(BROADCAST, StartDCRound, DCNetwork_.nodeID());
        DCNetwork_.outbox().push(startDCRound);
    }
    else {
        uint32_t groupManager = DCNetwork_.members().at(minimumID).connectionID();

        // send a ready message
        OutgoingMessage readyMessage(groupManager, ReadyMessage, DCNetwork_.nodeID());
        DCNetwork_.outbox().push(readyMessage);

        // wait for the round start message
        auto receivedMessage = DCNetwork_.inbox().pop();
        if(receivedMessage.msgType() != StartDCRound)
            std::cout << "Ready State: inappropriate message received" << std::endl;
    }
    // perform a state transition
    return std::make_unique<SecuredInitialRound>(DCNetwork_);
}