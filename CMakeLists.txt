cmake_minimum_required(VERSION 3.15)
project(threePP)

set(CMAKE_CXX_STANDARD 17)
set(GCC_COVERAGE_COMPILE_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}")

include_directories(/usr/local/include)

# local test
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
        src/dc/UnsecuredInitialRound.cpp
        src/dc/UnsecuredFinalRound.cpp
        src/dc/FairnessProtocol.cpp
        src/network/UnsecuredP2PConnection.cpp
        src/network/UnsecuredNetworkManager.cpp
        src/dc/BlameProtocol.cpp
)

target_link_libraries(
        threePP
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)

#docker version
add_executable(
        dockerInstance
        src/docker/ThreePP.cpp
        src/network/Node.cpp
        src/network/P2PConnection.cpp
        src/datastruct/OutgoingMessage.cpp
        src/network/NetworkManager.cpp
        src/network/UnsecuredP2PConnection.cpp
        src/network/UnsecuredNetworkManager.cpp
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
        src/dc/UnsecuredInitialRound.cpp
        src/dc/UnsecuredFinalRound.cpp
        src/dc/FairnessProtocol.cpp
)

target_link_libraries(
        dockerInstance
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)

add_executable(
        dockerAuthority
        src/docker/NodeAuthority.cpp
        src/network/Node.cpp
        src/network/P2PConnection.cpp
        src/datastruct/OutgoingMessage.cpp
        src/network/NetworkManager.cpp
        src/network/UnsecuredP2PConnection.cpp
        src/network/UnsecuredNetworkManager.cpp
        src/datastruct/ReceivedMessage.cpp
        src/datastruct/NetworkMessage.cpp
)

target_link_libraries(
        dockerAuthority
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)



# for tests only
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

# for tests only
add_executable(
        networkTest
        src/test/networkTest.cpp
        src/network/UnsecuredNetworkManager.cpp
)

target_link_libraries(
        networkTest
        -L/usr/local/lib
        -pthread
        -lcryptopp
)

add_executable(
        floodAndPrune
        src/test/FloodAndPruneTest.cpp
        src/network/Node.cpp
        src/network/P2PConnection.cpp
        src/datastruct/OutgoingMessage.cpp
        src/network/NetworkManager.cpp
        src/datastruct/MessageBuffer.cpp
        src/datastruct/BufferedMessage.cpp
        src/network/MessageHandler.cpp
        src/datastruct/ReceivedMessage.cpp
        src/utils/Utils.cpp
        src/datastruct/MessageType.h
        src/datastruct/NetworkMessage.cpp
)

target_link_libraries(
        floodAndPrune
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)

add_executable(
        adaptiveDiffusion
        src/test/AdaptiveDiffusionTest.cpp
        src/network/Node.cpp
        src/network/P2PConnection.cpp
        src/datastruct/OutgoingMessage.cpp
        src/network/NetworkManager.cpp
        src/datastruct/MessageBuffer.cpp
        src/datastruct/BufferedMessage.cpp
        src/network/MessageHandler.cpp
        src/datastruct/ReceivedMessage.cpp
        src/utils/Utils.cpp
        src/datastruct/MessageType.h
        src/datastruct/NetworkMessage.cpp
        src/ad/VirtualSource.cpp
        src/ad/AdaptiveDiffusion.h
)

target_link_libraries(
        adaptiveDiffusion
        -L/usr/local/lib
        -pthread
        -lcrypto
        -lssl
        -lcryptopp
)

