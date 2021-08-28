/*
	Better description
*/
#include <string.h>
#include <string>

using std::string;

#include <vector>
#include <unistd.h>
#include <iostream>
#include <tins/tins.h>
#include <chrono>

#include "include/Sender.h"
#include "include/Receiver.h"

#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>
#include <fstream>

using namespace Tins;
using namespace std;

std::chrono::high_resolution_clock::time_point time_of_last_packet_;
std::chrono::high_resolution_clock::time_point time_received_;
std::chrono::duration<double, std::milli> time_span_;
double last_packet_timestamp_;
string message_to_send = "";


int main(int argc, char **argv) {
//    Load config file
    Json::Value config;
    std::ifstream config_file("../config.json", std::ifstream::binary);
    config_file >> config;
    message_to_send = config["message_to_send"].asString();
    Globals::load_globals(config);

    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {
            Receiver receiver = Receiver();
        }
        else if (!strcmp(argv[1], "--client")) {
            // Configuring parameters
            bool is_encrypted = config["cryptography"]["is_encrypted"].asBool();
            Sender sender = Sender(Globals::covert_channel_type_, is_encrypted, Globals::cipher_type_);
            for(int i=0; i<Globals::number_of_repeat_;i++){
                sender.send_message(message_to_send);
                sleep(2);
            }
            return 0;
        }
    }
    else {
        std::cerr << "Bad usage";
        return 1;
    }
}
