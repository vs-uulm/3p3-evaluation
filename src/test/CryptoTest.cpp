#include <iostream>

#include <cryptopp/eccrypto.h>
#include <cryptopp/ecpoint.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>

typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element EC_Point;

/* Test program used to generate two EC points G and H which are
 * required for the EC Pedersen Commitments */
int main() {
    std::string input = "This is some test input";
    CryptoPP::SHA256 sha256;

    std::string hashed;
    sha256.Update(reinterpret_cast<CryptoPP::byte*>(input.data()), input.size());
    hashed.resize(sha256.DigestSize());
    sha256.Final(reinterpret_cast<CryptoPP::byte*>(hashed.data()));

    // CryptoPP
    std::cout << "Vector " << std::endl;
    for(uint8_t c : hashed) {
        std::cout << std::hex << (int) c;
    }
    std::cout << std::endl;

    std::string hashed_string;
    sha256.Update(reinterpret_cast<CryptoPP::byte*>(input.data()), input.size());
    hashed_string.resize(sha256.DigestSize());
    sha256.Final(reinterpret_cast<CryptoPP::byte*>(hashed_string.data()));

    // CryptoPP
    std::cout << "String " << std::endl;
    for(uint8_t c : hashed_string) {
        std::cout << std::hex << (int) c;
    }
    std::cout << std::endl;

    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::OID curveID = CryptoPP::ASN1::secp256k1();

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    CryptoPP::Integer seed(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    EC_Point G = ec_group.ExponentiateBase(seed);

    CryptoPP::Integer psi(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    EC_Point H = ec_group.GetCurve().ScalarMultiply(G, psi);

    std::cout << "Seed: " << std::endl << std::hex << seed << std::endl;

    std::cout << "G:" << std::endl;
    std::cout << "  " << std::hex << G.x << std::endl;
    std::cout << "  " << std::hex << G.y << std::endl;

    std::cout << "Psi " << std::endl << std::hex << psi << std::endl;
    std::cout << "H:" << std::endl;
    std::cout << "  " << std::hex << H.x << std::endl;
    std::cout << "  " << std::hex << H.y << std::endl;

    return 0;
}
