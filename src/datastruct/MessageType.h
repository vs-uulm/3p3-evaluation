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

    InitialRoundCommitments,
    InitialRoundFirstSharing,
    InitialRoundSecondSharing,
    InitialRoundFinished,

    FinalRoundCommitments,
    FinalRoundFirstSharing,
    FinalRoundSecondSharing,
    FinalRoundFinished,

    InvalidShare,

    BlameRoundCommitments,
    BlameRoundFirstSharing,
    BlameRoundSecondSharing,
    BlameRoundFinished,

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
    DCLoggingMessage,
    FairnessLoggingMessage,

    // Control Mesage
    TerminateMessage
};

#endif //THREEPP_MESSAGETYPE_H
