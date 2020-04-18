#include <cryptopp/eccrypto.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/asn.h>
#include <cryptopp/crc.h>
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

    CryptoPP::Integer d(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::Integer z(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());

    CryptoPP::Integer w = r*z + d;
    w = w.Modulo(ec_group.GetSubgroupOrder());

    CryptoPP::Integer rz = r*z;
    rz = rz.Modulo(ec_group.GetSubgroupOrder());

    CryptoPP::ECPPoint wG = ec_group.GetCurve().ScalarMultiply(G, w);

    CryptoPP::ECPPoint rzG = ec_group.GetCurve().ScalarMultiply(G, rz);
    CryptoPP::ECPPoint dG = ec_group.GetCurve().ScalarMultiply(G, d);

    CryptoPP::ECPPoint rzG_dG = ec_group.GetCurve().Add(rzG, dG);

    std::cout << "wG" << std::endl;
    std::cout << std::hex << wG.x << std::endl;
    std::cout << std::hex << wG.y << std::endl;

    std::cout << "rzG + dG" << std::endl;
    std::cout << std::hex << rzG_dG.x << std::endl;
    std::cout << std::hex << rzG_dG.y << std::endl;

    CryptoPP::Integer r_(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::Integer x(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());

    CryptoPP::Integer rr_ = r + r_;

    CryptoPP::ECPPoint rG = ec_group.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint r_G = ec_group.GetCurve().ScalarMultiply(G, r_);

    CryptoPP::ECPPoint xH = ec_group.GetCurve().ScalarMultiply(H, x);

    CryptoPP::ECPPoint rr_G = ec_group.GetCurve().ScalarMultiply(G, rr_);

    CryptoPP::ECPPoint C = ec_group.GetCurve().Add(rG, xH);

    CryptoPP::ECPPoint C_ = ec_group.GetCurve().Add(rr_G, xH);

    CryptoPP::ECPPoint CC_ = ec_group.GetCurve().Add(C_, ec_group.GetCurve().Inverse(C));

    std::cout << "C:" << std::endl;
    std::cout << std::hex << C.x << std::endl;
    std::cout << std::hex << C.y << std::endl;

    std::cout << "C_:" << std::endl;
    std::cout << std::hex << C_.x << std::endl;
    std::cout << std::hex << C_.y << std::endl;

    std::cout << "r_G:" << std::endl;
    std::cout << std::hex << r_G.x << std::endl;
    std::cout << std::hex << r_G.y << std::endl;

    std::cout << "CC_:" << std::endl;
    std::cout << std::hex << CC_.x << std::endl;
    std::cout << std::hex << CC_.y << std::endl;

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
