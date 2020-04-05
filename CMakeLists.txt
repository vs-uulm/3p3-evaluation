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
        src/dc/Init.cpp
        src/dc/Ready.cpp
        src/datastruct/MessageType.h
        src/dc/DCState.h
        src/datastruct/NetworkMessage.cpp
        src/dc/RoundOne.cpp
        src/dc/RoundTwo.cpp
        src/dc/DCMember.cpp
)

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
