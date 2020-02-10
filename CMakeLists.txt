cmake_minimum_required(VERSION 3.15)
project(threePP)

set(CMAKE_CXX_STANDARD 11)

include_directories(/usr/local/include)

add_executable(
        threePP
        src/test/test.cpp
        src/network/node.cpp
        src/network/peer.cpp
        src/network/p2p_connection.cpp
        src/network/peer_handler.cpp
)

target_link_libraries(
        threePP
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
)