#include <iostream>
#include <boost/asio/io_service.hpp>
#include <boost/asio.hpp>
//#include "../network/NetworkManager.h"

int main() {
    using namespace boost::asio;
    using ip::tcp;
    //using boost::asio::ip::udp;
    boost::asio::io_service io_service;
    tcp::socket socket(io_service);

    ip::address ip_address;
    socket.connect(tcp::endpoint(ip::address::from_string("8.8.8.8"), 443));
    ip_address = socket.local_endpoint().address();
    socket.close();
    std::cout << ip_address.to_string() << std::endl;

    /*
    MessageQueue<ReceivedMessage> inbox1;
    MessageQueue<ReceivedMessage> inbox2;

    io_context io_context1;
    uint16_t port1 = 8888;
    ip::address_v4 ip_address(ip::address_v4::from_string("127.0.0.1"));

    NetworkManager networkManager1(io_context1, port1, inbox1);
    // Run the io_context which handles the network manager
    std::thread networkThread1([&io_context1]() {
        std::cout << "Thread 1 started" << std::endl;
        io_context1.run();
    });

    io_context io_context2;
    uint16_t port2 = 9999;

    NetworkManager networkManager2(io_context1, port2, inbox2);
    // Run the io_context which handles the network manager
    std::thread networkThread2([&io_context2]() {
        std::cout << "Thread 2 started" << std::endl;
        io_context2.run();
    });
    // Do work here

    Node node(0, 8888, ip_address);
    int receiverID = networkManager2.addNeighbor(node);

    size_t msgSize = std::pow(2,10);
    std::cout << std::dec << msgSize << std::endl;

    for(uint32_t i = 0; i < 20000; i++) {
        std::vector<uint8_t> testData(msgSize);
        OutgoingMessage testMessage(receiverID, 0, 0, std::move(testData));
        networkManager2.sendMessage(std::move(testMessage));
        //std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "Received " << std::dec << inbox1.size() << std::endl;

    // End
    networkThread1.join();
    std::cout << " Thread 1 finished" << std::endl;
    networkThread2.join();
    std::cout << " Thread 2 finished" << std::endl;
    return 0;
     */
}