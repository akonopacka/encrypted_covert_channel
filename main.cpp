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
#include <thread>
#include <bitset>
#include <sstream>
#include <cstdlib>
#include <iomanip>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <unistd.h>
//#include "include/Globals.h"
#include "include/Sender.h"

#include "include/Cryptographer.h"
#include "include/Receiver.h"

#include <jsoncpp/json/json.h>
#include <jsoncpp/json/value.h>
#include <fstream>

using namespace Tins;
using namespace std;

std::string message_;
std::chrono::high_resolution_clock::time_point time_of_last_packet_;
std::chrono::high_resolution_clock::time_point time_received_;
std::chrono::duration<double, std::milli> time_span_;
double last_packet_timestamp_;

// "timing", "storage", "IP_id", "HTTP", "LSB", "sequence", "loss"
string covert_channel_type = "";
string message_to_send = "";

/* A 256 bit key */
unsigned char *key = (unsigned char *) "01234567890123456789012345678901";

/* A 128 bit IV */
unsigned char *iv = (unsigned char *) "0123456789012345";

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


int main(int argc, char **argv) {

    Json::Value config;
    std::ifstream config_file("../config.json", std::ifstream::binary);
    config_file >> config;

    covert_channel_type = config["covert_channel_type"].asString();
    message_to_send = config["message_to_send"].asString();


    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {
            Receiver receiver = Receiver();
            if (covert_channel_type == "storage") {
                std::cout << "Server! - Storage method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 1234");
                Sniffer("lo").sniff_loop(receiver.storage_callback);
            } else if (covert_channel_type == "IP_id") {
                std::cout << "Server! - IP_id method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 1234");
                Sniffer("lo").sniff_loop(receiver.IP_id_callback);

            }
            else if (covert_channel_type == "HTTP") {
                std::cout << "Server! - HTTP method\n";
                receiver.HTTP_callback();
            }
            else if (covert_channel_type == "LSB") {
                std::cout << "Server! - LSB Hop limit method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 1234");
                Sniffer("lo").sniff_loop(receiver.LSB_Hop_callback);
            }
            else if (covert_channel_type == "sequence") {
                std::cout << "Server! - sequence method\n";

                Globals::message_="";
                Globals::last_seq_ = 1;
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp.dstport==1234");
                sniffer.sniff_loop(receiver.sequence_callback);
            }
            else if (covert_channel_type == "loss") {
                std::cout << "Server! - Loss method\n";
                Globals::message_="";
                Globals::last_seq_ = 1;
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp.dstport==1234");
                sniffer.sniff_loop(receiver.loss_callback);
            }
            else if (covert_channel_type == "timing") {
                std::cout << "Server! - Timing method\n";
                SnifferConfiguration sniffer_configuration = SnifferConfiguration();
                sniffer_configuration.set_immediate_mode(false);
                Sniffer sniffer("lo", sniffer_configuration);
                sniffer.set_filter("udp&&port 1234");
                sniffer.sniff_loop(receiver.timing_callback);
            }
        }
    }

    if (!strcmp(argv[1], "--client")) {
//      Configuring parameters
        Globals::IP_address = config["server_IP_address"].asString();
        Globals::dst_port_ = config["dst_port"].asInt();
        Globals::src_port_ = config["src_port"].asInt();

        Sender sender = Sender(covert_channel_type);
        sender.send_message(message_to_send);
        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }
}
