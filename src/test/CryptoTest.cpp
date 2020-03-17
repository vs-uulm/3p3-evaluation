#include <iostream>

#include <cryptopp/eccrypto.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <boost/asio/detail/array.hpp>
#include <iomanip>
#include <bitset>
#include <valarray>
#include "../datastruct/NetworkMessage.h"
#include "../datastruct/MessageType.h"

const CryptoPP::ECPPoint G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                            CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const CryptoPP::ECPPoint H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                            CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));

/* Test program used to generate two EC points G and H which are
 * required for the EC Pedersen Commitments */
int main() {
    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    //std::cout << point << std::endl;
    CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::Integer s(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::ECPPoint first = ec_group.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint second = ec_group.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint C = ec_group.GetCurve().Add(first, second);

    uint32_t pointSize1 = ec_group.GetEncodedElementSize(true);
    CryptoPP::byte encodedPoint[pointSize1];

    uint32_t pointSize2 = ec_group.GetEncodedElementSize(false);
    CryptoPP::byte compressedPoint[pointSize2];

    std::cout << "Uncompressed:" << std::endl;
    ec_group.EncodeElement(true, C, encodedPoint);
    int i = 0;
    for(CryptoPP::byte c : encodedPoint) {
        if(i == 1 || i == 33)
            std::cout << " ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
        i++;
    }
    std::cout << std::endl << std::endl;

    std::cout << "Compressed:" << std::endl;
    ec_group.EncodeElement(true, C, compressedPoint);
    for(CryptoPP::byte c : compressedPoint) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    }
    std::cout << std::endl;

    uint32_t size1 = ec_group.GetCurve().EncodedPointSize(true);
    std::cout << std::dec <<  "Size: " << size1 << std::endl;

    CryptoPP::byte final[size1];
    ec_group.GetCurve().EncodePoint(final, C, true);
    for(CryptoPP::byte c : final) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    }
    std::cout << std::endl << std::endl;

    CryptoPP::Integer integer(ec_group.GetMaxExponent());
    CryptoPP::byte encodedInt[32];
    size_t encodedSize = integer.MinEncodedSize(CryptoPP::Integer::UNSIGNED);
    integer.Encode(encodedInt, 30, CryptoPP::Integer::UNSIGNED);
    std::cout << std::dec << "Size: " << encodedSize << std::endl;
    /*
    using namespace CryptoPP;

    DL_GroupParameters_EC<ECP> curve;
    curve.Initialize(CryptoPP::ASN1::secp256k1());

    Integer generator(PRNG, Integer::One(), curve.GetMaxExponent());
    ECPPoint testPoint = curve.ExponentiateBase(generator);

    uint32_t uncompressedSize = curve.GetEncodedElementSize(true);
    uint32_t compressedSize = curve.GetEncodedElementSize(false);

    byte compressedPoint[compressedSize];
    byte uncompressedPoint[uncompressedSize];

    // uncompressed
    curve.EncodeElement(true, testPoint, uncompressedPoint);
    for(byte b : uncompressedPoint)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) b;
    std::cout << std::endl;

    // compressed
    curve.EncodeElement(false, testPoint, compressedPoint);
    for(byte b : compressedPoint)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) b;
    std::cout << std::endl;
    */

    /*
    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group_r1;
    ec_group_r1.Initialize(CryptoPP::ASN1::secp256r1());

    CryptoPP::Integer maximum_k1 = ec_group.GetMaxExponent();
    std::cout << "Maximum K1:  " << std::hex << maximum_k1 << std::endl;

    CryptoPP::Integer maximum_r1 = ec_group_r1.GetMaxExponent();
    std::cout << "Maximum R1:  " << std::hex << maximum_r1 << std::endl;

    CryptoPP::Integer seed(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::ECPPoint G = ec_group.ExponentiateBase(seed);

    CryptoPP::Integer psi(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::ECPPoint H = ec_group.GetCurve().ScalarMultiply(G, psi);

    std::cout << "Seed: " << std::endl << std::hex << seed << std::endl;

    std::cout << "G:" << std::endl;
    std::cout << "  " << std::hex << G.x << std::endl;
    std::cout << "  " << std::hex << G.y << std::endl;

    std::cout << "Psi " << std::endl << std::hex << psi << std::endl;
    std::cout << "H:" << std::endl;
    std::cout << "  " << std::hex << H.x << std::endl;
    std::cout << "  " << std::hex << H.y << std::endl;
     */
    return 0;
}
