//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_SENDER_H
#define ENCRYPTED_COVERT_CHANNEL_SENDER_H


#include <string>
#include <bitset>
#include <iostream>
#include <tins/tins.h>
#include <chrono>
#include <thread>
using namespace std;
using namespace Tins;



class Sender {
    string message;
    string method = "timing";
    string ip_source_address = "127.0.0.1";

public:
    Sender(const string &message, const string &method);

    void send_with_timing_method();

    void send_with_storage_method();
};


#endif //ENCRYPTED_COVERT_CHANNEL_SENDER_H
