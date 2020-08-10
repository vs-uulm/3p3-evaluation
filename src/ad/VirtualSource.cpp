#include <cmath>
#include <set>
#include <random>
#include <algorithm>
#include <thread>

#include "VirtualSource.h"
#include "AdaptiveDiffusion.h"
#include "../datastruct/MessageType.h"

VirtualSource::VirtualSource(uint32_t nodeID, std::vector<uint32_t>& neighbors,
        MessageQueue<OutgoingMessage>& outboxThreePP, MessageQueue<ReceivedMessage>& inboxThreePP, std::vector<uint8_t> message,
        ReceivedMessage VSToken, bool safetyMechanism)
: nodeID_(nodeID), message_(message), outboxThreePP_(outboxThreePP), inboxThreePP_(inboxThreePP),
  randomEngine_(std::random_device()()), uniformDistribution_(0, 1), safetyMechanism_(safetyMechanism) {

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
        OutgoingMessage adForward(neighbor, AdaptiveDiffusionForward, nodeID_, message_);
        outboxThreePP_.push(std::move(adForward));
    }
}

double VirtualSource::p(uint16_t s, uint16_t h) {
    if(AdaptiveDiffusion::Eta == 2)
        return (s-2*h+2)/(s+2.0);
    else
        return (std::pow(AdaptiveDiffusion::Eta-1, s/2.0-h+1)-1)
                    / (std::pow(AdaptiveDiffusion::Eta-1, s/2.0+1)-1);
}

std::vector<uint8_t> VirtualSource::generateVSToken(uint16_t s, uint16_t h, std::vector<uint8_t>& message) {
    std::vector<uint8_t> VSToken(36);

    // set s
    VSToken[0] = (s & 0xFF00) >> 8;
    VSToken[1] = (s & 0x00FF);

    // set h
    VSToken[2] = (h & 0xFF00) >> 8;
    VSToken[3] = (h & 0x00FF);

    std::string msgHash = utils::sha256(message);
    std::copy(msgHash.begin(), msgHash.end(), &VSToken[4]);

    return VSToken;
}

size_t VirtualSource::maxRemainingSteps() {
    size_t delta = AdaptiveDiffusion::maxDepth - 2 - s;

    if(delta > 0)
        return 2 * delta;
    else
        return 0;
}

void VirtualSource::executeTask() {
    VirtualSource::spreadMessage();

    if((s < AdaptiveDiffusion::maxDepth) && (s > 1))
        VirtualSource::spreadMessage();

    h += 1;
    s += 2;

    while(s <= AdaptiveDiffusion::maxDepth) {
        s += 1;
        if(p(s,h) <= uniformDistribution_(randomEngine_)) {
            VirtualSource::spreadMessage();
        } else {
            uint32_t r = PRNG.GenerateWord32(0, neighbors_.size()-1);
            uint32_t v_next = *std::next(neighbors_.begin(), r);
            std::vector<uint8_t> VSToken = generateVSToken(s, h, message_);
            OutgoingMessage vsForward(v_next, VirtualSourceToken, nodeID_, std::move(VSToken));
            outboxThreePP_.push(std::move(vsForward));
            break;
        }
    }

    // if the maximum depth has been reached, the flood and prune protocol is initiated
    if(AdaptiveDiffusion::floodAndPrune) {
        if (s >= AdaptiveDiffusion::maxDepth) {
            ReceivedMessage floodMessage(SELF, FloodAndPrune, nodeID_, std::move(message_));
            inboxThreePP_.push(std::move(floodMessage));
        }

        else if(safetyMechanism_) {
            // sleep until the maximum number of steps has been reached
            // and inject the message into the own inbox
            size_t maxTime = AdaptiveDiffusion::propagationDelay * maxRemainingSteps();
            std::this_thread::sleep_for(std::chrono::milliseconds(maxTime));

            ReceivedMessage floodMessage(SELF, FloodAndPrune, nodeID_, std::move(message_));
            inboxThreePP_.push(std::move(floodMessage));
        }
    }
}