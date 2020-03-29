#ifndef THREEPP_MESSAGETYPE_H
#define THREEPP_MESSAGETYPE_H

enum MessageType {
    HelloMessage,
    HelloResponse,
    ReadyMessage,
    StartDCRound,
    CommitmentRoundOne,
    RoundOneSharingPartOne,
    RoundOneSharingPartTwo,
    RestartRoundOne,
    BlameMessage,
    CommitmentRoundTwo,
    RoundTwoSharingPartOne,
    RoundTwoSharingPartTwo
};

#endif //THREEPP_MESSAGETYPE_H
