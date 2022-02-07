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
#include "include/Cryptographer.h"

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
        //    Load config file
        Json::Value config;
        std::ifstream config_file("../config.json", std::ifstream::binary);
        config_file >> config;
        message_to_send = config["message_to_send"].asString();
        Globals::load_globals(config);
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
        } else if (!strcmp(argv[1], "--crypto_test")){
            Globals::cipher_type_ = argv[2];
            string plaintext = "All that is gold does not glitter,\nNot all those who wander are lost;\nThe old that is strong does not wither,\nDeep roots are not reached by the frost.\nFrom the ashes a fire shall be woken,\nA light from the shadows shall spring;\nRenewed shall be blade that was broken,\nThe crownless again shall be king. J.R.R. Tolkien, The Fellowship of the Ring";
            plaintext = plaintext+ plaintext+plaintext;
            stringstream ss(argv[3]);
            int sleep_value = 100;
            if(!(ss >> sleep_value)){
                cout<< "Parsing sleeping time not successfull"<<endl;
            }
//            cout<<"Waiting time: "<<sleep_value<<endl;

            usleep(sleep_value);
            Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
            for (int i=0;i<5;i++){
                if (Globals::cipher_type_ == "aes") {
                    string encrypted_part = cryptographer.encrypt_aes_("AAAAAAAAAAAAAAAA");
                } else if (Globals::cipher_type_ == "des") {
                    string encrypted_part = cryptographer.encrypt_des("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                } else if (Globals::cipher_type_ == "present") {
                    string encrypted_part = cryptographer.encrypt_present_("AAAAAAAA");
                } else if (Globals::cipher_type_ == "rsa") {
                    string encrypted_part = encrypt_rsa_("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
                } else if (Globals::cipher_type_ == "clefia") {
                    string encrypted_part = cryptographer.encrypt_clefia_("AAAAAAAAAAAAAAAA");
                } else if (Globals::cipher_type_ == "grain") {
                    string encrypted_part = cryptographer.encrypt_grain_("AAAAAAAAAA");
                }
            }

//            Cryptographer cryptographer = Cryptographer(Globals::cipher_type_);
//            string ciphertext = cryptographer.encrypt(plaintext);
//            cout<<"OUTPUT"<<message_to_send<<endl;
            usleep(sleep_value);
        }

    } else {
        std::cerr << "Bad usage";
        return 1;
    }
}
