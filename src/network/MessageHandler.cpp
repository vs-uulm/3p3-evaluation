#include <iostream>
#include "MessageHandler.h"
#include "../datastruct/MessageType.h"

MessageHandler::MessageHandler(uint32_t nodeID, MessageQueue<ReceivedMessage> &inbox,
        MessageQueue<ReceivedMessage> &inboxDCNet, MessageQueue<OutgoingMessage> &outbox)
        : inbox_(inbox), inboxDCNet_(inboxDCNet), outbox_(outbox), msgBuffer(0), nodeID_(nodeID) {}

void MessageHandler::run() {
    for(;;) {
        auto receivedMessage = inbox_.pop();

        switch(receivedMessage.msgType()) {
            case HelloMessage: {
                inboxDCNet_.push(receivedMessage);
                OutgoingMessage response(receivedMessage.connectionID(), HelloResponse, nodeID_);
                outbox_.push(response);
                break;
            }
            case HelloResponse:
            case ReadyMessage:
            case StartDCRound:
            case RoundOneCommitments:
            case RoundOneSharingOne:
            case RoundOneSharingTwo:
            case RoundTwoCommitments:
            case RoundTwoSharingOne:
            case RoundTwoSharingTwo:
            case SeedRoundCommitments:
            case SeedRoundSharingOne:
            case SeedRoundSharingTwo:
            case BlameMessage:
            case ZeroKnowledgeCommitments:
            case ZeroKnowledgeCoinCommitments:
            case ZeroKnowledgeCoinSharingOne:
            case ZeroKnowledgeCoinSharingTwo:
            case ZeroKnowledgeOpenCommitments:
            case ZeroKnowledgeSigmaExchange:
            case ZeroKnowledgeSigmaResponse:
            case ZeroKnowledgeSigmaProof:
                inboxDCNet_.push(receivedMessage);
                break;
            default:
                std::cout << "Unknown message type received: " << receivedMessage.msgType() << std::endl;
        }
    }
}
