#include <iostream>
#include "MessageHandler.h"
#include "../datastruct/MessageType.h"

MessageHandler::MessageHandler(uint32_t nodeID, MessageQueue<ReceivedMessage> &inbox,
        MessageQueue<ReceivedMessage> &inboxDCNet, MessageQueue<OutgoingMessage> &outbox)
        : inbox_(inbox), inboxDCNet_(inboxDCNet), outbox_(outbox), msgBuffer(0), nodeID_(nodeID) {}

void MessageHandler::run() {
    for(;;) {
        auto receivedMessage = inbox_.pop();
        switch(receivedMessage->msgType()) {
            case HelloMessage: {
                inboxDCNet_.push(receivedMessage);
                OutgoingMessage response(receivedMessage->connectionID(), HelloResponse, nodeID_);
                outbox_.push(std::make_shared<OutgoingMessage>(response));
                break;
            }
            case HelloResponse:
            case ReadyMessage:
            case StartDCRound:
            case CommitmentRoundOne:
            case RoundOneSharingPartOne:
            case RoundOneSharingPartTwo:
            case CommitmentRoundTwo:
            case RoundTwoSharingPartOne:
            case RoundTwoSharingPartTwo:
            case BlameMessage:
                inboxDCNet_.push(receivedMessage);
                break;
            default:
                std::cout << "Unknown message type" << std::endl;
        }
    }
}
