#include <iostream>
#include "MessageHandler.h"
#include "../datastruct/MessageType.h"

MessageHandler::MessageHandler(uint32_t nodeID, MessageQueue<ReceivedMessage> &inbox,
        MessageQueue<ReceivedMessage> &inboxDCNet, MessageQueue<OutgoingMessage> &outbox)
        : nodeID_(nodeID), inbox_(inbox), inboxDCNet_(inboxDCNet), outbox_(outbox), msgBuffer(0) {}

void MessageHandler::run() {
    for(;;) {
        auto receivedMessage = inbox_.pop();
        switch(receivedMessage->msgType()) {
            case HelloMessage:
                inboxDCNet_.push(receivedMessage);
                createHelloResponse(receivedMessage);
                break;
            case HelloResponse:
            case ReadyMessage:
            case StartDCRound:
            case CommitmentRoundOne:
            case SharingOneRoundOne:
            case SharingTwoRoundOne:
                inboxDCNet_.push(receivedMessage);
                break;
            default:
                std::cout << "Unknown message type" << std::endl;
        }
    }
}

void MessageHandler::createHelloResponse(std::shared_ptr<ReceivedMessage>& helloMsg) {
    // create a response that contains the own nodeID
    //std::vector<uint8_t> nodeIDVector(reinterpret_cast<uint8_t*>(&nodeID_),
      //                                reinterpret_cast<uint8_t*>(&nodeID_) + sizeof(uint32_t));
    OutgoingMessage response(helloMsg->connectionID(), HelloResponse, nodeID_);
    outbox_.push(std::make_shared<OutgoingMessage>(response));
}
