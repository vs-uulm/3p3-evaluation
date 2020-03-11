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
        src/datastruct/NetworkMessage.cpp
        src/network/NetworkManager.cpp
        src/datastruct/MessageBuffer.cpp
        src/network/MessageHandler.cpp
        src/datastruct/ReceivedMessage.cpp
        src/crypto/Utils.cpp
        src/datastruct/BufferedMessage.cpp
        src/dc/DCNetworkState.h
        src/dc/ReadyState.cpp src/datastruct/DirectMessage.cpp src/datastruct/DirectMessage.h src/datastruct/MessageType.h)

target_link_libraries(
        threePP
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)

add_executable(
        cryptoTest
        src/test/CryptoTest.cpp
        src/threePP/DCNetwork.cpp
        src/dc/ReadyState.cpp src/dc/InitState.cpp src/dc/InitState.h)

target_link_libraries(
        cryptoTest
        -L/usr/local/lib
        -pthread
        -lcryptopp
)

add_executable(
        DCNetworkTest
        src/test/DCNetworkTest.cpp
        src/threePP/DCNetwork.cpp
        src/dc/ReadyState.cpp src/datastruct/DirectMessage.cpp src/datastruct/DirectMessage.h)

target_link_libraries(
        DCNetworkTest
        -L/usr/local/lib
        -pthread
        -lcryptopp
)
