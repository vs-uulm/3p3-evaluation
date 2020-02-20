#ifndef THREEPP_NETWORKMESSAGE_H
#define THREEPP_NETWORKMESSAGE_H

#include <unitypes.h>

class NetworkMessage {
public:
    NetworkMessage();
    NetworkMessage(int msg_type, uint16_t msg_len, uint8_t* payload);
    ~NetworkMessage();

    void add_type(int msg_type);
    void add_payload();
private:
    int msg_type_;
    uint16_t msg_len_;
    uint8_t* payload_;
};


#endif //THREEPP_NETWORKMESSAGE_H
