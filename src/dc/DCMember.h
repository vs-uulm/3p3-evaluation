#ifndef THREEPP_DCMEMBER_H
#define THREEPP_DCMEMBER_H

#include <cstdint>
#include <cryptopp/ecpoint.h>

class DCNetwork;

class DCMember {
public:
    DCMember(uint32_t nodeID, uint32_t connectionID);

    DCMember(uint32_t nodeID, uint32_t connectionID, CryptoPP::ECPPoint publicKey);

    uint32_t nodeID();

    uint32_t connectionID();

    const CryptoPP::ECPPoint& publicKey();

private:
    uint32_t nodeID_;

    uint32_t connectionID_;

    CryptoPP::ECPPoint publicKey_;
};


#endif //THREEPP_DCMEMBER_H
