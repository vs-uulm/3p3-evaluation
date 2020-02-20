cmake_minimum_required(VERSION 3.15)
project(threePP)

set(CMAKE_CXX_STANDARD 17)

include_directories(/usr/local/include)

add_executable(
        threePP
        src/test/test.cpp
        src/network/Node.cpp
        src/network/Peer.cpp
        src/network/P2PConnection.cpp
        src/network/NetworkMessage.cpp src/network/NetworkMessage.h src/network/NetworkManager.cpp src/network/NetworkManager.h)

target_link_libraries(
        threePP
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
)