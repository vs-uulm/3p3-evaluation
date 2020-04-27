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
    ZeroKnowledgeCoinCommitments,
    ZeroKnowledgeCoinSharingOne,
    ZeroKnowledgeCoinSharingTwo,
    ZeroKnowledgeOpenCommitments,
    ZeroKnowledgeSigmaExchange,
    ZeroKnowledgeSigmaResponse,
    ZeroKnowledgeSigmaProof
};

#endif //THREEPP_MESSAGETYPE_H
