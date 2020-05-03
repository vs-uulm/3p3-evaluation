#include <iostream>
#include "MessageHandler.h"
#include "../datastruct/MessageType.h"

MessageHandler::MessageHandler(uint32_t nodeID, MessageQueue<ReceivedMessage>& inboxThreePP,
                               MessageQueue<ReceivedMessage>& inboxDCNet, MessageQueue<OutgoingMessage>& outboxThreePP,
                               MessageQueue<std::vector<uint8_t>>& outboxFinal)
        : inboxThreePP_(inboxThreePP), inboxDCNet_(inboxDCNet), outboxThreePP_(outboxThreePP), outboxFinal_(outboxFinal),
          msgBuffer(0), nodeID_(nodeID) {}

void MessageHandler::run() {
    for (;;) {
        auto receivedMessage = inboxThreePP_.pop();

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
            case AdaptiveDiffusionMessage:
                if(!msgBuffer.contains(receivedMessage)) {
                    msgBuffer.insert(receivedMessage);
                    outboxFinal_.push(receivedMessage.body());
                } else {
                    // TODO sub-graph broadcast
                }
                break;
            case VirtualSourceToken:
                // TODO
                break;
            case FloodAndPrune: {
                if(!msgBuffer.contains(receivedMessage)) {
                    // Add the message to the message buffer
                    msgBuffer.insert(receivedMessage);

                    // flood the message
                    OutgoingMessage floodMessage(BROADCAST, FloodAndPrune, nodeID_, receivedMessage.connectionID(),
                                                 receivedMessage.body());
                    outboxThreePP_.push(std::move(floodMessage));

                    // pass the received message to the upper layer
                    outboxFinal_.push(std::move(receivedMessage.body()));
                } else if(msgBuffer.getType(receivedMessage) != FloodAndPrune) {
                    // only updates the message type
                    msgBuffer.insert(receivedMessage);
                }
                break;
            }
            default:
                std::cout << "Unknown message type received: " << receivedMessage.msgType() << std::endl;
        }
    }
}
