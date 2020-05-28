#ifndef THREEPP_MESSAGETYPE_H
#define THREEPP_MESSAGETYPE_H

enum MessageType {
    // Setup messages
    RegisterMessage,
    RegisterResponse,
    NodeInfoMessage,

    // DC-Network messages
    HelloMessage,
    HelloResponse,
    ReadyMessage,
    StartDCRound,

    RoundOneCommitments,
    RoundOneSharingOne,
    RoundOneSharingTwo,

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
    ZeroKnowledgeSigmaProof,

    FinalDCMessage,

    // Adaptive Diffusion messages
    AdaptiveDiffusionMessage,
    VirtualSourceToken,

    // Flood and Prune
    FloodAndPrune,

    // Evaluation
    DCLoggingMessage
};

#endif //THREEPP_MESSAGETYPE_H
