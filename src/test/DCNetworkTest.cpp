#include <iostream>
#include "../threePP/DCNetwork.h"

int main() {
    MessageQueue<std::vector<uint8_t>> send_queue;
    MessageQueue<ReceivedMessage> receive_queue;

    DCNetwork DCNet(send_queue, receive_queue);

    return 0;

}