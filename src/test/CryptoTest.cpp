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
#include <set>
#include <thread>
#include <string>
#include <sstream>

const CryptoPP::ECPPoint G(CryptoPP::Integer("362dc3caf8a0e8afd06f454a6da0cdce6e539bc3f15e79a15af8aa842d7e3ec2h"),
                            CryptoPP::Integer("b9f8addb295b0fd4d7c49a686eac7b34a9a11ed2d6d243ad065282dc13bce575h"));

const CryptoPP::ECPPoint H(CryptoPP::Integer("a3cf0a4b6e1d9146c73e9a82e4bfdc37ee1587bc2bf3b0c19cb159ae362e38beh"),
                            CryptoPP::Integer("db4369fabd3d770dd4c19d81ac69a1749963d69c687d7c4e12d186548b94cb2ah"));

std::mutex mut;

unsigned NUM_THREADS = 6;

uint32_t num_values = 256;
std::vector<std::vector<CryptoPP::ECPPoint>> testMatrix(num_values);

int main() {

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());
    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> threadCurve1;
    threadCurve1.Initialize(CryptoPP::ASN1::secp256k1());
    CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::Integer s(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
    CryptoPP::ECPPoint rG = threadCurve1.GetCurve().ScalarMultiply(G, r);
    CryptoPP::ECPPoint sH = threadCurve1.GetCurve().ScalarMultiply(H, s);
    CryptoPP::ECPPoint commitment = threadCurve1.GetCurve().Add(rG, sH);
    std::cout << "Test Point" << std::endl << std::hex << commitment.x << std::endl << commitment.y << std::endl;
    std::vector<uint8_t> encodingTest(33);
    //for(uint8_t c : encodingTest)
    //  std::cout << std::hex << (int) c;
    //  std::cout << std::endl;
    threadCurve1.GetCurve().EncodePoint(&encodingTest[0], commitment, true);
    for(uint8_t c : encodingTest)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) c;
    std::cout << std::endl;
    CryptoPP::ECPPoint decodedPoint2;
    threadCurve1.GetCurve().DecodePoint(decodedPoint2, &encodingTest[0], 33);
    std::cout << "Decoding Test" << std::endl << std::hex << decodedPoint2.x << std::endl << decodedPoint2.y << std::endl;

    CryptoPP::ECPPoint commitment1 = threadCurve1.GetCurve().CascadeMultiply(r, G, s, H);
    std::vector<uint8_t> encodingTest1(33);
    threadCurve1.GetCurve().EncodePoint(&encodingTest1[0], commitment1, true);
    CryptoPP::ECPPoint decodedPoint1;
    threadCurve1.GetCurve().DecodePoint(decodedPoint1, &encodingTest1[0], 33);
    std::cout << "Decoding Test" << std::endl << std::hex << decodedPoint1.x << std::endl << decodedPoint1.y << std::endl;

    size_t numPoints = std::pow(2,16);
    std::vector<CryptoPP::ECPPoint> testPoints;
    testPoints.reserve(numPoints);

    CryptoPP::AutoSeededRandomPool PRNG;
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
    ec_group.Initialize(CryptoPP::ASN1::secp256k1());

    auto start = std::chrono::high_resolution_clock::now();

    for(size_t i = 0; i < numPoints; i++) {
        CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
        //CryptoPP::Integer r(ec_group.GetMaxExponent());
        CryptoPP::ECPPoint rG = ec_group.GetCurve().ScalarMultiply(G, r);
        testPoints.push_back(std::move(rG));
    }
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;
    std::cout << "Generation: " << elapsed.count() << "s" <<std::endl;

    std::vector<uint8_t> encoded1(numPoints * 33);
    std::vector<uint8_t> encoded2(numPoints * 36);

    start = std::chrono::high_resolution_clock::now();

    for(size_t i = 0, offset = 0; i < numPoints; i++, offset += 33) {
        ec_group.GetCurve().EncodePoint(&encoded1[offset], testPoints[i],true);
    }

    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    std::cout << "Encoding 1: " << elapsed.count() << "s" <<std::endl;



    start = std::chrono::high_resolution_clock::now();

    for(size_t i = 0, offset = 0; i < numPoints; i++, offset += 36) {
        ec_group.GetCurve().EncodePoint(&encoded2[offset], testPoints[i],true);
    }

    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    std::cout << "Encoding 2: " << elapsed.count() << "s" <<std::endl;

    /*
    std::list<std::thread> threads;
    std::vector<std::vector<CryptoPP::ECPPoint>> testMatrix(num_values);
    start = std::chrono::high_resolution_clock::now();
    for(uint32_t i = 0; i < NUM_THREADS; i++) {
        uint32_t min = num_values / static_cast<double>(NUM_THREADS) * i;
        uint32_t max = num_values / static_cast<double>(NUM_THREADS) * (i+1);

        std::thread exec([min, max, &testMatrix](){
            {
                std::lock_guard<std::mutex> lock(mut);
                std::cout << "Thread started with min=" << min << " max=" << max << std::endl;
            }
            CryptoPP::AutoSeededRandomPool PRNG;
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> ec_group;
            ec_group.Initialize(CryptoPP::ASN1::secp256k1());
            std::vector<CryptoPP::ECPPoint> vec;
            vec.reserve(128);
            for(uint32_t i = min; i < max; i++) {
                for(uint32_t c = 0; c < 128; c++) {
                    CryptoPP::Integer r(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
                    CryptoPP::Integer s(PRNG, CryptoPP::Integer::One(), ec_group.GetMaxExponent());
                    // generate the commitment for the j-th slice of the i-th share
                    CryptoPP::ECPPoint rG = ec_group.GetCurve().ScalarMultiply(G, r);
                    CryptoPP::ECPPoint sH = ec_group.GetCurve().ScalarMultiply(H, s);
                    CryptoPP::ECPPoint commitment = ec_group.GetCurve().Add(rG, sH);
                    vec.push_back(std::move(commitment));
                }
                {
                    //std::lock_guard<std::mutex> lock(mut);
                    testMatrix[i] = std::move(vec);
                }
            }
        });
        threads.push_back(std::move(exec));
    }

    for(auto& t : threads)
        t.join();

    finish = std::chrono::high_resolution_clock::now();
    elapsed = finish - start;
    std::cout << "Finished in " << elapsed.count() << "s" <<std::endl;


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

    CryptoPP::ECPPoint Cr_G = ec_group.GetCurve().Add(C, r_G);

    CryptoPP::ECPPoint CC_ = ec_group.GetCurve().Add(C_, ec_group.GetCurve().Inverse(C));

    std::cout << "C:" << std::endl;
    std::cout << std::hex << C.x << std::endl;
    std::cout << std::hex << C.y << std::endl;

    std::cout << "C_:" << std::endl;
    std::cout << std::hex << C_.x << std::endl;
    std::cout << std::hex << C_.y << std::endl;

    std::cout << "Cr_G:" << std::endl;
    std::cout << std::hex << Cr_G.x << std::endl;
    std::cout << std::hex << Cr_G.y << std::endl;

    std::cout << "r_G:" << std::endl;
    std::cout << std::hex << r_G.x << std::endl;
    std::cout << std::hex << r_G.y << std::endl;

    std::cout << "CC_:" << std::endl;
    std::cout << std::hex << CC_.x << std::endl;
    std::cout << std::hex << CC_.y << std::endl;

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
