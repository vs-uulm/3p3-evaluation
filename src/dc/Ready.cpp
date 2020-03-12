#include <iostream>
#include "Ready.h"
#include "RoundOne.h"
#include "../datastruct/MessageType.h"

#include <thread>
#include <chrono>

Ready::Ready() {}

Ready::~Ready() {}

std::unique_ptr<DCState> Ready::executeTask(DCNetwork& DCNet) {
    std::cout << "Entering Ready State" << std::endl;
    uint32_t minimumID = DCNet.nodeID();
    // determine whether the local node has the smallest nodeID
    for(auto& member : DCNet.members())
        if(member.first < minimumID)
            minimumID = member.first;

    // this node acts as the group manager
    if(minimumID == DCNet.nodeID()) {
        size_t memberCount = DCNet.members().size();
        std::vector<uint32_t> readyNodes;
        readyNodes.reserve(memberCount);

        while(readyNodes.size() < memberCount) {
            auto readyMessage = DCNet.inbox().pop();
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
        DCNet.outbox().push(std::make_shared<OutgoingMessage>(startDCRound));
    }
    else {
        uint32_t groupManager = DCNet.members().at(minimumID);

        // send a ready message
        OutgoingMessage readyMessage(groupManager, ReadyMessage);
        DCNet.outbox().push(std::make_shared<OutgoingMessage>(readyMessage));

        // wait for the round start message
        auto receivedMessage = DCNet.inbox().pop();
        if(receivedMessage->msgType() != StartDCRound)
            std::cout << "inappropriate message received" << std::endl;
    }

    // perform a state transition
    return std::make_unique<RoundOne>();
}