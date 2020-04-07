#ifndef THREEPP_MESSAGETYPE_H
#define THREEPP_MESSAGETYPE_H

enum MessageType {
    RegisterMessage,
    RegisterResponse,
    NodeInfoMessage,
    HelloMessage,
    HelloResponse,
    ReadyMessage,
    StartDCRound,
    CommitmentRoundOne,
    RoundOneSharingPartOne,
    RoundOneSharingPartTwo,
    CommitmentRoundTwo,
    RoundTwoSharingPartOne,
    RoundTwoSharingPartTwo,
    BlameMessage
};

#endif //THREEPP_MESSAGETYPE_H
