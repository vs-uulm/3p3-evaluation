#include <iostream>

#include <cryptopp/eccrypto.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/drbg.h>
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

CryptoPP::Hash_DRBG<> DRNG;

/* Test program used to generate two EC points G and H which are
 * required for the EC Pedersen Commitments */
int main() {
    size_t b = 32;
    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::byte seed[b];
    PRNG.GenerateBlock(seed, b);

    CryptoPP::Hash_DRBG<> PRNG1;
    CryptoPP::Hash_DRBG<> PRNG2;

    PRNG1.IncorporateEntropy(seed, 16);
    PRNG2.IncorporateEntropy(seed, 17);

    CryptoPP::byte stream1[32];
    CryptoPP::byte stream2[32];

    PRNG1.GenerateBlock(stream1, 32);
    PRNG2.GenerateBlock(stream2, 32);

    for(uint8_t c : stream1)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout << std::endl;

    for(uint8_t c : stream2)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout << std::endl;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    std::cout << "Maximum Exponent: " << std::endl << std::hex << ec_group.GetMaxExponent() << std::endl;
    std::cout << "Subgroup order: " << std::endl << ec_group.GetSubgroupOrder() << std::endl;

    CryptoPP::Integer r1(ec_group.GetMaxExponent() - 23);
    std::cout << std::hex <<  "r1: " << r1 << std::endl;
    CryptoPP::Integer r2(ec_group.GetMaxExponent() - 46);
    std::cout << std::hex <<  "r2: " << r2 << std::endl;
    CryptoPP::Integer r3 = (r1 + r2).Modulo(ec_group.GetSubgroupOrder());
    std::cout << std::hex <<  "r3: " << r3 << std::endl;

    CryptoPP::Integer x1(ec_group.GetMaxExponent() - 75);
    CryptoPP::Integer x2(ec_group.GetMaxExponent() - 97);
    CryptoPP::Integer x3 = (x1 + x2).Modulo(ec_group.GetSubgroupOrder());

    CryptoPP::ECPPoint r1G = ec_group.GetCurve().ScalarMultiply(G, r1);
    CryptoPP::ECPPoint x1H = ec_group.GetCurve().ScalarMultiply(H, x1);
    CryptoPP::ECPPoint C1 = ec_group.GetCurve().Add(r1G, x1H);

    CryptoPP::ECPPoint r2G = ec_group.GetCurve().ScalarMultiply(G, r2);
    CryptoPP::ECPPoint x2H = ec_group.GetCurve().ScalarMultiply(H, x2);
    CryptoPP::ECPPoint C2 = ec_group.GetCurve().Add(r2G, x2H);

    CryptoPP::ECPPoint C3_first =  ec_group.GetCurve().Add(C2, C1);

    CryptoPP::ECPPoint r3G = ec_group.GetCurve().ScalarMultiply(G, r3);
    CryptoPP::ECPPoint x3H = ec_group.GetCurve().ScalarMultiply(H, x3);
    CryptoPP::ECPPoint C3_second = ec_group.GetCurve().Add(r3G, x3H);

    std::cout << "First: " << std::endl;
    std::cout << std::hex << C3_first.x << std::endl;
    std::cout << std::hex << C3_first.y << std::endl;

    std::cout << "Second: " << std::endl;
    std::cout << std::hex << C3_second.x << std::endl;
    std::cout << std::hex << C3_second.y << std::endl;

    /*
    CryptoPP::Integer maximum_k1 = ec_group.GetMaxExponent();
    std::cout << "Maximum K1:  " << std::hex << maximum_k1 << std::endl;

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
