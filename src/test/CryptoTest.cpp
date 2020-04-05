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

    CryptoPP::ECIES<CryptoPP::ECP>::Decryptor privateKey(PRNG, CryptoPP::ASN1::secp384r1());

    CryptoPP::ECIES<CryptoPP::ECP>::Encryptor publicKey(privateKey);


    CryptoPP::ECDH<CryptoPP::ECP>::Domain dhA(CryptoPP::ASN1::secp256k1()), dhB(CryptoPP::ASN1::secp256k1());
    CryptoPP::SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    CryptoPP::SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());

    dhA.GenerateKeyPair(PRNG, privA, pubA);
    dhB.GenerateKeyPair(PRNG, privB, pubB);

    std::cout << dhA.PublicKeyLength() << std::endl;


    CryptoPP::SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

    dhA.Agree(sharedA, privA, pubB);

    dhB.Agree(sharedB, privB, pubA);


    CryptoPP::Integer ssa, ssb;

    ssa.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    std::cout << "(A): " << std::hex << ssa << std::endl;

    ssb.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    std::cout << "(B): " << std::hex << ssb << std::endl;

    std::cout << "Agreed to shared secret" << std::endl;

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
