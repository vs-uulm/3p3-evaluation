#include <cryptopp/eccrypto.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/drbg.h>
#include <cryptopp/modes.h>
#include <iostream>
#include <iomanip>

const CryptoPP::ECPPoint G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                            CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const CryptoPP::ECPPoint H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                            CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));

int main() {
    CryptoPP::AutoSeededRandomPool PRNG;

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::byte seed[32];
    PRNG.GenerateBlock(seed, 32);

    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption DRNG1;

    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption DRNG2;

    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption DRNG3;

    for(int i=0; i<10; i++) {
        PRNG.GenerateBlock(seed, 32);
        DRNG1.SetKeyWithIV(seed, 16, seed+16, 16);
        DRNG2.SetKeyWithIV(seed, 16, seed+16, 16);
        DRNG3.SetKeyWithIV(seed, 16, seed+16, 16);
        CryptoPP::Integer i1(DRNG1, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
        CryptoPP::Integer i2(DRNG2, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
        CryptoPP::Integer i3(DRNG3, CryptoPP::Integer::One(), ec_group.GetMaxExponent());

        std::cout << "I1:" << std::hex << i1 << std::endl;
        std::cout << "I2:" << std::hex << i2 << std::endl;
        std::cout << "I3:" << std::hex << i3 << std::endl << std::endl;
    }
    /*
    CryptoPP::Integer seed(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());

    CryptoPP::ECPPoint empty;

    CryptoPP::ECPPoint point1 = ec_group.ExponentiateBase(seed);
    CryptoPP::ECPPoint point2 = ec_group.GetCurve().ScalarMultiply(point1, seed);
    CryptoPP::ECPPoint point3 = ec_group.GetCurve().ScalarMultiply(point2, seed);

    CryptoPP::ECPPoint test1 = ec_group.GetCurve().Add(empty, point1);
    test1 = ec_group.GetCurve().Add(test1, point2);
    test1 = ec_group.GetCurve().Add(test1, point3);
    std::cout << "First" << std::endl;
    std::cout << std::hex << test1.x << std::endl << test1.y << std::endl << std::endl;

    CryptoPP::ECPPoint test2 = ec_group.GetCurve().Add(empty, point3);
    test2 = ec_group.GetCurve().Add(test2, point2);
    test2 = ec_group.GetCurve().Add(test2, point1);
    std::cout << "second" << std::endl;
    std::cout << std::hex << test2.x << std::endl << test2.y << std::endl << std::endl;
     */

    //prng.SetKeyWithIV(seed, 32, seed + 32, 16);
    /*
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::Integer r1("c9bb432af142d9ff2ee65d3995f886bb6c57bb70e207df3104bc53bc7f41f015h");
    std::cout << std::hex <<  "r1: " << r1 << std::endl;
    CryptoPP::Integer r2("991bbe52bfe8f8b79210f230097b235959adff76b158a134b5872f474ee74aa6h");
    std::cout << std::hex <<  "r2: " << r2 << std::endl;
    CryptoPP::Integer r3("d02043984478522191c33815f102eb28d41804b46cf06d964e385d4df8873ba4h");
    std::cout << std::hex <<  "r3: " << r3 << std::endl;
    CryptoPP::Integer R = (r1 + r2 + r3).Modulo(ec_group.GetSubgroupOrder());
    std::cout << std::hex <<  "R:  " << R << std::endl;
    std::cout << std::endl;

    CryptoPP::Integer message("000000000000000000000000000000005c7c00200000000000000000000000h");
    CryptoPP::Integer x1("eb281e3eed97e1bf4c82760f8d44f97e82e7d79824b09ed0ee216521d526a628h");
    std::cout << std::hex <<  "x1: " << x1 << std::endl;
    CryptoPP::Integer x2("a7564bd6f21d0f6fde3190d3138a81c246c51ea2f6f41c81b398d0559d82fa6h");
    std::cout << std::hex <<  "x2: " << x2 << std::endl;
    CryptoPP::Integer x3 = (message - (x1 + x2)).Modulo(ec_group.GetSubgroupOrder());
    std::cout << std::hex <<  "x3: " << x3 << std::endl;
    CryptoPP::Integer X = (x1 + x2 + x3).Modulo(ec_group.GetSubgroupOrder());
    std::cout << std::hex <<  "X:  " << X << std::endl;
    std::cout << std::endl;

    CryptoPP::ECPPoint r1G = ec_group.GetCurve().ScalarMultiply(G, r1);
    CryptoPP::ECPPoint x1H = ec_group.GetCurve().ScalarMultiply(H, x1);
    CryptoPP::ECPPoint C1 = ec_group.GetCurve().Add(r1G, x1H);
    uint8_t compressedC1[33];
    ec_group.GetCurve().EncodePoint(compressedC1, C1, true);
    for(uint8_t c : compressedC1)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout << std::endl;

    CryptoPP::ECPPoint r2G = ec_group.GetCurve().ScalarMultiply(G, r2);
    CryptoPP::ECPPoint x2H = ec_group.GetCurve().ScalarMultiply(H, x2);
    CryptoPP::ECPPoint C2 = ec_group.GetCurve().Add(r2G, x2H);
    uint8_t compressedC2[33];
    ec_group.GetCurve().EncodePoint(compressedC2, C2, true);
    for(uint8_t c : compressedC2)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout << std::endl;


    CryptoPP::ECPPoint r3G = ec_group.GetCurve().ScalarMultiply(G, r3);
    CryptoPP::ECPPoint x3H = ec_group.GetCurve().ScalarMultiply(H, x3);
    CryptoPP::ECPPoint C3 = ec_group.GetCurve().Add(r3G, x3H);
    uint8_t compressedC3[33];
    ec_group.GetCurve().EncodePoint(compressedC3, C3, true);
    for(uint8_t c : compressedC3)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout << std::endl;

    CryptoPP::ECPPoint sumC = ec_group.GetCurve().Add(C2, C1);
    sumC = ec_group.GetCurve().Add(C3, sumC);

    CryptoPP::ECPPoint RG = ec_group.GetCurve().ScalarMultiply(G, R);
    CryptoPP::ECPPoint XH = ec_group.GetCurve().ScalarMultiply(H, X);
    CryptoPP::ECPPoint RXC = ec_group.GetCurve().Add(RG, XH);

    std::cout << "First: " << std::endl;
    std::cout << std::hex << sumC.x << std::endl;
    std::cout << std::hex << sumC.y << std::endl;
    std::cout << std::endl;

    std::cout << "Second: " << std::endl;
    std::cout << std::hex << RXC.x << std::endl;
    std::cout << std::hex << RXC.y << std::endl;
    */

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
