/*
	Better description
*/
#include <string>
#include <unistd.h>
#include <iostream>
#include <tins/tins.h>
#include <chrono>
#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>
#include <fstream>

#include "include/Sender.h"
#include "include/Receiver.h"

using namespace Tins;
using namespace std;

string message_to_send = "";

int main(int argc, char **argv) {
//    Load config file
    Json::Value config;
    std::ifstream config_file("../config.json", std::ifstream::binary);
    config_file >> config;
    message_to_send = config["message_to_send"].asString();
    Globals::load_globals(config);

    if (argc > 1) {
        if (argc > 2) {
            Globals::covert_channel_type_ = argv[2];
        }
        if (argc > 3) {
            if (!strcmp(argv[3], "--is_encrypted"))
                Globals::is_encrypted = true;
        }
        if (argc > 4) {
            Globals::cipher_type_ = argv[4];
        }
        if (!strcmp(argv[1], "--server")) {
            std::cout << "Starting server..." << endl;
            Receiver receiver = Receiver();
        } else if (!strcmp(argv[1], "--client")) {
            // Configuring parameters
            Sender sender = Sender(Globals::covert_channel_type_, Globals::is_encrypted, Globals::cipher_type_);
            for (int i = 0; i < Globals::number_of_repeat_; i++) {
                sender.send_message(message_to_send);
                sleep(2);
            }
            return 0;
        }
    } else {
        std::cerr << "Bad usage";
        return 1;
    }
}
