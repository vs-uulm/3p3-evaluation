#include <iostream>
#include <thread>
#include "MessageHandler.h"
#include "../datastruct/MessageType.h"
#include "../ad/AdaptiveDiffusion.h"
#include "../ad/VirtualSource.h"

MessageHandler::MessageHandler(uint32_t nodeID, std::vector<uint32_t>& neighbors,
                               MessageQueue<ReceivedMessage>& inboxThreePP, MessageQueue<ReceivedMessage>& inboxDCNet,
                               MessageQueue<OutgoingMessage>& outboxThreePP, MessageQueue<std::vector<uint8_t>>& outboxFinal,
                               uint32_t propagationDelay, uint32_t msgBufferSize)
        : inboxThreePP_(inboxThreePP), inboxDCNet_(inboxDCNet), outboxThreePP_(outboxThreePP), outboxFinal_(outboxFinal),
          msgBuffer(msgBufferSize), nodeID_(nodeID), propagationDelay_(propagationDelay), neighbors_(neighbors) {}

void MessageHandler::run() {
    for (;;) {
        auto receivedMessage = inboxThreePP_.pop();

        // simulate a network propagation delay
        std::chrono::duration<double> timeDifference = std::chrono::system_clock::now() - receivedMessage.timestamp();
        std::chrono::milliseconds delay = std::chrono::milliseconds(propagationDelay_)
                                                - std::chrono::duration_cast<std::chrono::milliseconds>(timeDifference);
        if(delay.count() > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(delay.count()));

        switch (receivedMessage.msgType()) {
            case HelloMessage: {
                inboxDCNet_.push(receivedMessage);
                OutgoingMessage response(receivedMessage.connectionID(), HelloResponse, nodeID_);
                outboxThreePP_.push(std::move(response));
                DCMembers_.insert(receivedMessage.connectionID());
                break;
            }
            case HelloResponse:
                DCMembers_.insert(receivedMessage.connectionID());
                inboxDCNet_.push(std::move(receivedMessage));
                break;
            case ReadyMessage:
            case StartDCRound:
            case RoundOneCommitments:
            case RoundOneSharingOne:
            case RoundOneSharingTwo:
            case RoundTwoCommitments:
            case RoundTwoSharingOne:
            case RoundTwoSharingTwo:
            case BlameMessage:
            case ZeroKnowledgeCommitments:
            case ZeroKnowledgeCoinCommitments:
            case ZeroKnowledgeCoinSharingOne:
            case ZeroKnowledgeCoinSharingTwo:
            case ZeroKnowledgeOpenCommitments:
            case ZeroKnowledgeSigmaExchange:
            case ZeroKnowledgeSigmaResponse:
            case ZeroKnowledgeSigmaProof:
                inboxDCNet_.push(std::move(receivedMessage));
                break;
            case FinalDCMessage:
                msgBuffer.insert(receivedMessage);
                outboxFinal_.push(receivedMessage.body());
                break;
            case AdaptiveDiffusionMessage:
                if(!msgBuffer.contains(receivedMessage)) {
                    msgBuffer.insert(receivedMessage);
                    outboxFinal_.push(receivedMessage.body());
                } else if(receivedMessage.senderID() > 1) {
                    uint32_t TTL = receivedMessage.senderID()-1;
                    std::set<uint32_t> neighborsSubset;
                    while(neighborsSubset.size() <  std::min(AdaptiveDiffusion::Eta, neighbors_.size())) {
                        uint32_t neighbor = PRNG.GenerateWord32(0, neighbors_.size()-1);
                        neighborsSubset.insert(neighbors_[neighbor]);
                    }
                    for(uint32_t neighbor : neighbors_) {
                        OutgoingMessage adForward(neighbor, AdaptiveDiffusionMessage, TTL, receivedMessage.body());
                        outboxThreePP_.push(std::move(adForward));
                    }
                }
                break;
            case VirtualSourceToken: {
                std::string msgHash(&receivedMessage.body()[4], &receivedMessage.body()[36]);
                std::vector<uint8_t> message = msgBuffer.getMessage(msgHash).body();
                std::thread virtualSourceThread([=]() {
                    VirtualSource virtualSource(nodeID_, neighbors_, outboxThreePP_, inboxThreePP_, message, receivedMessage);
                    virtualSource.executeTask();
                });
                virtualSourceThread.detach();
                break;
            }
            case FloodAndPrune: {
                if(!msgBuffer.contains(receivedMessage)) {
                    // Add the message to the message buffer
                    msgBuffer.insert(receivedMessage);

                    // flood the message
                    OutgoingMessage floodMessage(BROADCAST, FloodAndPrune, nodeID_, receivedMessage.connectionID(),
                                                 receivedMessage.body());
                    outboxThreePP_.push(std::move(floodMessage));

                    // pass the received message to the upper layer
                    if(receivedMessage.senderID() != SELF)
                        outboxFinal_.push(std::move(receivedMessage.body()));
                } else if(msgBuffer.getType(receivedMessage) != FloodAndPrune) {
                    // only updates the message type
                    msgBuffer.insert(receivedMessage);

                    // flood the message
                    OutgoingMessage floodMessage(BROADCAST, FloodAndPrune, nodeID_, receivedMessage.connectionID(),
                                                 receivedMessage.body());
                    outboxThreePP_.push(std::move(floodMessage));
                }
                break;
            }
            default:
                std::cout << "Unknown message type received: " << (int) receivedMessage.msgType() << std::endl;
        }
    }
}
