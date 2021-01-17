#ifndef ENCRYPTED_COVERT_CHANNEL_RECEIVER_H
#define ENCRYPTED_COVERT_CHANNEL_RECEIVER_H

#include <string>
#include <chrono>
#include <tins/tins.h>
#include <iostream>
#include <bitset>
#include <sstream>
#include "Globals.h"
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include "Cryptographer.h"


using namespace std;
using std::string;
using namespace Tins;

class Receiver {
public:
    Receiver();

    static bool timing_callback(const PDU &pdu);

    static bool storage_callback(const PDU &pdu);

    static bool IP_id_callback(const PDU &pdu);

    void HTTP_callback();

    static bool LSB_Hop_callback(const PDU &pdu);

    static bool sequence_callback(const PDU &pdu);

    static bool loss_callback(const PDU &pdu);
};


#endif //ENCRYPTED_COVERT_CHANNEL_RECEIVER_H
