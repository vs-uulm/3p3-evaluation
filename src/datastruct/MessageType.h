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
    RoundOneCommitments,
    RoundOneSharingOne,
    RoundOneSharingTwo,
    SeedRoundCommitments,
    SeedRoundSharingOne,
    SeedRoundSharingTwo,
    RoundTwoCommitments,
    RoundTwoSharingOne,
    RoundTwoSharingTwo,
    BlameMessage,
    BlameProtocolCommitments,
    BlameProtocolSharingOne,
    BlameProtocolSharingTwo,
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
