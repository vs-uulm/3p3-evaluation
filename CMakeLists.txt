cmake_minimum_required(VERSION 3.15)
project(threePP)

set(CMAKE_CXX_STANDARD 17)

include_directories(/usr/local/include)

add_executable(
        threePP
        src/test/NetworkTest.cpp
        src/network/Node.cpp
        src/network/Peer.cpp
        src/network/P2PConnection.cpp
        src/network/NetworkMessage.cpp
        src/network/NetworkManager.cpp
        src/datastruct/MessageQueue.cpp
        src/datastruct/MessageBuffer.cpp
        src/network/MessageHandler.cpp
        src/network/ReceivedMessage.cpp
        src/crypto/Utils.cpp
        src/test/TestData.h)

target_link_libraries(
        threePP
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
)