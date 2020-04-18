cmake_minimum_required(VERSION 3.15)
project(threePP)

set(CMAKE_CXX_STANDARD 17)
set(GCC_COVERAGE_COMPILE_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")

include_directories(/usr/local/include)

add_executable(
        threePP
        src/test/mainTest.cpp
        src/network/Node.cpp
        src/network/P2PConnection.cpp
        src/datastruct/OutgoingMessage.cpp
        src/network/NetworkManager.cpp
        src/datastruct/MessageBuffer.cpp
        src/datastruct/BufferedMessage.cpp
        src/network/MessageHandler.cpp
        src/datastruct/ReceivedMessage.cpp
        src/utils/Utils.cpp
        src/dc/DCNetwork.cpp
        src/dc/InitState.cpp
        src/dc/ReadyState.cpp
        src/datastruct/MessageType.h
        src/dc/DCState.h
        src/datastruct/NetworkMessage.cpp
        src/dc/SecuredInitialRound.cpp
        src/dc/SecuredFinalRound.cpp
        src/dc/DCMember.cpp
        src/dc/SeedRound.cpp
        src/dc/UnsecuredInitalRound.cpp src/dc/UnsecuredInitalRound.h src/dc/UnsecuredFinalRound.cpp src/dc/UnsecuredFinalRound.h)

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
)

target_link_libraries(
        cryptoTest
        -L/usr/local/lib
        -pthread
        -lcryptopp
)

add_executable(
        networkTest
        src/test/networkTest.cpp
        src/network/Node.cpp
        src/network/NetworkManager.cpp
        src/network/P2PConnection.cpp
        src/datastruct/NetworkMessage.cpp
        src/datastruct/ReceivedMessage.cpp
        src/datastruct/OutgoingMessage.cpp
)

target_link_libraries(
        networkTest
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)



