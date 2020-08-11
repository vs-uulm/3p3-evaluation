#ifndef THREEPP_VIRTUALSOURCE_H
#define THREEPP_VIRTUALSOURCE_H

#include <cstdint>
#include <vector>
#include <set>
#include <random>
#include <cryptopp/osrng.h>

#include "../datastruct/MessageQueue.h"
#include "../datastruct/OutgoingMessage.h"
#include "../datastruct/ReceivedMessage.h"

class VirtualSource {
public:
    VirtualSource(uint32_t nodeID, std::vector<uint32_t>& neighbors, MessageQueue<OutgoingMessage>& outboxThreePP,
                  MessageQueue<ReceivedMessage>& inboxThreePP, std::vector<uint8_t> message, ReceivedMessage VSToken,
                  bool safetyMechanism = false);

    void executeTask();

    void spreadMessage();

    double p(uint16_t s, uint16_t h);

    size_t maxRemainingSteps();

    static std::vector<uint8_t> generateVSToken(uint16_t s, uint16_t h, std::vector<uint8_t>& message);

private:
    uint16_t s;

    uint16_t h;

    uint32_t nodeID_;

    std::vector<uint8_t> message_;

    std::set<uint32_t> neighbors_;

    MessageQueue<OutgoingMessage>& outboxThreePP_;

    MessageQueue<ReceivedMessage>& inboxThreePP_;

    std::default_random_engine randomEngine_;

    std::uniform_real_distribution<double> uniformDistribution_;

    CryptoPP::AutoSeededRandomPool PRNG;

    bool safetyMechanism_;
};


#endif //THREEPP_VIRTUALSOURCE_H
