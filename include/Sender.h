//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_SENDER_H
#define ENCRYPTED_COVERT_CHANNEL_SENDER_H


#include <string>
#include <iostream>
#include <tins/tins.h>
#include <chrono>
#include <thread>
#include <cctype>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "/usr/include/arpa/inet.h"
#include <sys/types.h>

#include "Globals.h"
#include "Cryptographer.h"
#include "Evaluation.h"

using namespace std;
using namespace std::chrono;
using namespace Tins;


class Sender {
    string method = "timing";
    bool is_encrypted = true;
    string cipher_type = "aes";

public:

    Sender(const string &method, bool is_encrypted, string cipher_type);

    void send_with_timing_method(string message_to_send);

    void send_with_storage_method(string message_to_send);

    void send_with_storage_method_IP_id(string message_to_send);

    void send_with_HTTP_case_method(string message_to_send);

    void send_with_LSB_Hop_method(string message_to_send);

    void send_with_sequence_method(string message_to_send);

    void send_with_loss_method(string message_to_send);

    void send_message(string message_to_send);
};


#endif //ENCRYPTED_COVERT_CHANNEL_SENDER_H
