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
    CommitmentSeedRound,
    SeedRoundSharingPartOne,
    SeedRoundSharingPartTwo,
    CommitmentRoundTwo,
    RoundTwoSharingPartOne,
    RoundTwoSharingPartTwo,
    BlameMessage,
    ZeroKnowledgeCommitments,
    ZeroKnowledgeSharingOne,
    ZeroKnowledgeSharingTwo,
    ZeroKnowledgeProof
};

#endif //THREEPP_MESSAGETYPE_H
