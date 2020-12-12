#ifndef ENCRYPTED_COVERT_CHANNEL_RECEIVER_H
#define ENCRYPTED_COVERT_CHANNEL_RECEIVER_H

#include <string>
#include <chrono>
#include <tins/tins.h>
#include <iostream>
#include <bitset>
#include <sstream>
//#include "Globals.h"

using namespace std;
using std::string;
using namespace Tins;

class Receiver {
public:
    Receiver();

    static bool timing_callback(const PDU &pdu);

private:
//    string message;
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int decryptedtext_len, ciphertext_len;
//    std::chrono::high_resolution_clock::time_point time_of_last_packet = std::chrono::high_resolution_clock::now();
//    std::chrono::high_resolution_clock::time_point time_received;
//    std::chrono::duration<double, std::milli> time_span;
//    double last_packet_timestamp = 0;

};


#endif //ENCRYPTED_COVERT_CHANNEL_RECEIVER_H
