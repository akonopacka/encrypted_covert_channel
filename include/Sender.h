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
#include "../src/MethodTypeEnum.cpp"
using namespace std;
using namespace Tins;


class Sender {
    string method = "timing";
    string ip_source_address = "127.0.0.1";
    enum MethodTypeEnum methodTypeEnum ;

public:
    Sender(const string &method);
    void send_with_timing_method(const string message_to_send);
    void send_with_storage_method(const string message_to_send);
    void send_message(const string message_to_send);
};


#endif //ENCRYPTED_COVERT_CHANNEL_SENDER_H
