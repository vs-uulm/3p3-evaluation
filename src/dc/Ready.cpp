#include <iostream>
#include "Ready.h"
#include "RoundOne.h"

#include <thread>
#include <chrono>

Ready::Ready() {}

Ready::~Ready() {}

std::unique_ptr<DCState> Ready::executeTask(DCNetwork& DCNet) {
    uint32_t nodeID = DCNet.nodeID();
    //std::cout << "Ready Task" << std::endl;

    // perform a state transition
    return std::make_unique<RoundOne>();
}