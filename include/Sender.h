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
#include "Globals.h"
#include <iostream>
#include "../cpp-httplib-master/httplib.h"
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
#include <string>

#include <iostream>

#include <cpr/cpr.h>
#include <stdio.h> /* printf, sprintf */
#include <stdlib.h> /* exit */
#include <unistd.h> /* read, write, close */
#include <string.h> /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */



using namespace std;


using namespace std;
using namespace Tins;


class Sender {
    string method = "timing";
    string ip_source_address = "127.0.0.1";
    enum MethodTypeEnum methodTypeEnum;

public:
    Sender(const string &method);

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
