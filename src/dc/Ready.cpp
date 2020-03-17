#include <iostream>
#include "Ready.h"
#include "RoundOne.h"
#include "../datastruct/MessageType.h"

#include <thread>
#include <chrono>

Ready::Ready(DCNetwork& DCNet) : DCNetwork_(DCNet) {}

Ready::~Ready() {}

std::unique_ptr<DCState> Ready::executeTask() {
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

        while(readyNodes.size() < memberCount) {
            auto readyMessage = DCNetwork_.inbox().pop();
            if(readyMessage->msgType() != ReadyMessage) {
                std::cout << "Inappropriate message received: " << (int) readyMessage->msgType() << std::endl;
            }
            else {
                auto position = std::find(readyNodes.begin(), readyNodes.end(), readyMessage->connectionID());
                if(position == readyNodes.end())
                    readyNodes.push_back(readyMessage->connectionID());
            }
        }
        // the loop is terminated when all members of the DC network are ready
        std::cout << "all ready messages received" << std::endl;
        OutgoingMessage startDCRound(-1, StartDCRound);
        DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(startDCRound));
    }
    else {
        uint32_t groupManager = DCNetwork_.members().at(minimumID);

        // send a ready message
        OutgoingMessage readyMessage(groupManager, ReadyMessage);
        DCNetwork_.outbox().push(std::make_shared<OutgoingMessage>(readyMessage));

        // wait for the round start message
        auto receivedMessage = DCNetwork_.inbox().pop();
        if(receivedMessage->msgType() != StartDCRound)
            std::cout << "inappropriate message received" << std::endl;
    }

    // perform a state transition
    return std::make_unique<RoundOne>(DCNetwork_);
}