#ifndef THREEPP_MESSAGETYPE_H
#define THREEPP_MESSAGETYPE_H

enum MessageType {
    // Setup messages
    Register,
    RegisterResponse,
    NodeInfo,

    // DC-Network messages
    DCConnect,
    DCConnectResponse,

    InitialRoundCommitments,
    InitialRoundFirstSharing,
    InitialRoundSecondSharing,
    InvalidShare,
    InitialRoundFinished,

    FinalRoundCommitments,
    FinalRoundFirstSharing,
    FinalRoundSecondSharing,
    FinalRoundFinished,

    DCNetworkReceived,

    BlameRoundCommitments,
    BlameRoundFirstSharing,
    BlameRoundSecondSharing,
    BlameRoundFinished,

    ProofOfFairnessCommitments,
    MultipartyCoinFlipCommitments,
    MultipartyCoinFlipFirstSharing,
    MultipartyCoinFlipSecondSharing,
    ProofOfFairnessOpenCommitments,
    ProofOfFairnessSigmaExchange,
    ProofOfFairnessSigmaResponse,
    ProofOfFairnessZeroKnowledgeProof,

    // Adaptive Diffusion messages
    AdaptiveDiffusionForward,
    VirtualSourceToken,

    // Flood and Prune
    FloodAndPrune,

    // Evaluation
    DCNetworkLogging,
    TerminateMessage,
    FairnessLogging
};

#endif //THREEPP_MESSAGETYPE_H
