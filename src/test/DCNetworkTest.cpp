#include <iostream>
#include "../threePP/DC_Network.h"

int main() {
    DC_Network DC_network(32);

    std::string msg = "This is a test message";
    DC_network.send_msg(msg);

    return 0;

}