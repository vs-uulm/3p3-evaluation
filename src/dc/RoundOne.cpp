#include <iostream>
#include <thread>
#include "RoundOne.h"
#include "Init.h"

RoundOne::RoundOne() {
}

RoundOne::~RoundOne() {

}

std::unique_ptr<DCState> RoundOne::executeTask(DCNetwork& DCNet) {
    std::cout << "Entering round one" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(60));
    return std::make_unique<Init>();
}