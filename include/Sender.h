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
#include "Globals.h"
#include <iostream>
#include <iostream>
#include <ctype.h>
#include <cstring>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sstream>
#include <fstream>

#include <stdio.h> /* printf, sprintf */
#include <stdlib.h> /* exit */
#include <unistd.h> /* read, write, close */
#include <string.h> /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */
#include "/usr/include/arpa/inet.h"

#include "Cryptographer.h"
#include "Evaluation.h"


using namespace std;
using namespace std::chrono;
using namespace Tins;


class Sender {
    string method = "timing";
    bool is_encrypted = true;
    string cipher_type = "aes";
    Evaluation evaluation = Evaluation();

public:

    Sender(const string &method, bool is_encrypted, string cipher_type);

    void send_with_timing_method(const string message_to_send);

    void send_with_storage_method(const string message_to_send);

    void send_with_storage_method_IP_id(const string message_to_send);

    void send_with_HTTP_case_method(const string message_to_send);

    void send_with_LSB_Hop_method(const string message_to_send);

    void send_with_sequence_method(const string message_to_send);

    void send_with_loss_method(const string message_to_send);

    void send_message(const string message_to_send);
};


#endif //ENCRYPTED_COVERT_CHANNEL_SENDER_H
