#include <iostream>
#include "ReadyState.h"
#include "InitState.h"

ReadyState::ReadyState() {
    std::cout << "ReadyState constructor" << std::endl;
}

ReadyState::~ReadyState() {
    std::cout << "ReadyState destructor" << std::endl;
}

std::unique_ptr<DCState> ReadyState::executeTask(DCNetwork& DCNet) {
    std::cout << "ReadyState Task" << std::endl;

    // transition
    return std::make_unique<InitState>();
}