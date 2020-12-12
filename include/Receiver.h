#ifndef ENCRYPTED_COVERT_CHANNEL_RECEIVER_H
#define ENCRYPTED_COVERT_CHANNEL_RECEIVER_H

#include <string>
#include <chrono>
#include <tins/tins.h>
#include <iostream>
#include <bitset>
#include <sstream>
#include "Globals.h"

using namespace std;
using std::string;
using namespace Tins;

class Receiver {
public:
    Receiver();

    static bool timing_callback(const PDU &pdu);
    static bool storage_callback(const PDU &pdu);

private:
//    string message_;
////    unsigned char ciphertext[128];
////    unsigned char decryptedtext[128];
////    int decryptedtext_len, ciphertext_len;
//    static std::chrono::high_resolution_clock::time_point time_of_last_packet_;
//    static std::chrono::high_resolution_clock::time_point time_received_;
//    static std::chrono::duration<double, std::milli> time_span_;
//    static double last_packet_timestamp_;

};


#endif //ENCRYPTED_COVERT_CHANNEL_RECEIVER_H
