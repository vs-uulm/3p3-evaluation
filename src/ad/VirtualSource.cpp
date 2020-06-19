#include <cmath>
#include <set>
#include <random>
#include <algorithm>
#include <thread>

#include "VirtualSource.h"
#include "AdaptiveDiffusion.h"
#include "../datastruct/MessageType.h"

VirtualSource::VirtualSource(uint32_t nodeID, std::vector<uint32_t>& neighbors,
        MessageQueue<OutgoingMessage>& outboxThreePP, MessageQueue<ReceivedMessage>& inboxThreePP, std::vector<uint8_t> message)
: s(0), h(0), numForwards(0), nodeID_(nodeID), message_(message), outboxThreePP_(outboxThreePP), inboxThreePP_(inboxThreePP),
  randomEngine_(std::random_device()()), uniformDistribution_(0, 1) {
    // select a random subset of neighbors
    while(neighbors_.size() < std::min(AdaptiveDiffusion::Eta, neighbors.size())) {
        uint32_t neighbor = PRNG.GenerateWord32(0, neighbors.size()-1);
        neighbors_.insert(neighbors[neighbor]);
    }
}

VirtualSource::VirtualSource(uint32_t nodeID, std::vector<uint32_t>& neighbors,
        MessageQueue<OutgoingMessage>& outboxThreePP, MessageQueue<ReceivedMessage>& inboxThreePP, std::vector<uint8_t> message,
        ReceivedMessage VSToken)
: numForwards(0), nodeID_(nodeID), message_(message), outboxThreePP_(outboxThreePP), inboxThreePP_(inboxThreePP),
  randomEngine_(std::random_device()()), uniformDistribution_(0, 1) {

    // select a random subset of neighbors
    while(neighbors_.size() < std::min(AdaptiveDiffusion::Eta, neighbors.size()-1)) {
        uint32_t neighbor = PRNG.GenerateWord32(0, neighbors.size()-1);
        if(neighbor != VSToken.connectionID())
            neighbors_.insert(neighbors[neighbor]);
    }

    s = (VSToken.body()[0] << 8) | VSToken.body()[1];
    h = (VSToken.body()[2] << 8) | VSToken.body()[3];
}

void VirtualSource::spreadMessage() {
    for(uint32_t neighbor : neighbors_) {
        // use the senderID header field as TTL field
        OutgoingMessage adForward(neighbor, AdaptiveDiffusionMessage, numForwards+1, message_);
        outboxThreePP_.push(std::move(adForward));
    }
    numForwards++;
}

void VirtualSource::executeTask() {
    VirtualSource::spreadMessage();

    if((s < AdaptiveDiffusion::maxDepth) && (s > 1))
        VirtualSource::spreadMessage();

    h += 1;
    s += 2;

    while(s < AdaptiveDiffusion::maxDepth) {
        s += 1;
        if(AdaptiveDiffusion::p(s,h) <= uniformDistribution_(randomEngine_)) {
            VirtualSource::spreadMessage();
        } else {
            uint32_t r = PRNG.GenerateWord32(0, neighbors_.size()-1);
            uint32_t v_next = *std::next(neighbors_.begin(), r);
            std::vector<uint8_t> VSToken = AdaptiveDiffusion::generateVSToken(s, h, message_);

            OutgoingMessage vsForward(v_next, VirtualSourceToken, nodeID_, std::move(VSToken));
            outboxThreePP_.push(std::move(vsForward));
            break;
        }
    }

    // if the maximum depth has been reached, the flood and prune protocol is initiated
    if(s >= AdaptiveDiffusion::maxDepth) {
        ReceivedMessage floodMessage(SELF, FloodAndPrune, nodeID_, std::move(message_));
        inboxThreePP_.push(std::move(floodMessage));
    } else {
        // otherwise: sleep until the maximum number of steps has been reached
        // and inject the message in the own inbox
        size_t maxTime = AdaptiveDiffusion::RTT * AdaptiveDiffusion::maxRemainingSteps(s);
        std::this_thread::sleep_for(std::chrono::milliseconds(maxTime));

        ReceivedMessage floodMessage(SELF, FloodAndPrune, nodeID_, std::move(message_));
        inboxThreePP_.push(std::move(floodMessage));
    }
}