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


using namespace Tins;
using namespace std;

std::string message_;
std::chrono::high_resolution_clock::time_point time_of_last_packet_;
std::chrono::high_resolution_clock::time_point time_received_;
std::chrono::duration<double, std::milli> time_span_;
double last_packet_timestamp_;

string message_to_send = "One_two_three";

/* A 256 bit key */
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

/* A 128 bit IV */
unsigned char *iv = (unsigned char *)"0123456789012345";


string covert_channel_type = "IP_identificator";


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {
            Receiver receiver = Receiver();
            if(covert_channel_type!="timing"){
                std::cout << "Server! - Storage method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 22");
                Sniffer("lo").sniff_loop(receiver.storage_callback);
            }
            else{
                std::cout << "Server! - Timing method\n";
                SnifferConfiguration sniffer_configuration = SnifferConfiguration();
                sniffer_configuration.set_immediate_mode(false);
                Sniffer sniffer("lo", sniffer_configuration);
//                Receiver receiver = Receiver();
                sniffer.set_filter("udp&&port 22");
                sniffer.sniff_loop(receiver.timing_callback);
            }
        }
    }

    if (!strcmp(argv[1], "--client")) {
        /* Message to be encrypted */
        unsigned char *plaintext =
                (unsigned char *)"OLAAAAAAAAAAAA1";

        /*
         * Buffer for ciphertext. Ensure the buffer is long enough for the
         * ciphertext which may be longer than the plaintext, depending on the
         * algorithm and mode.
         */
        unsigned char ciphertext[128];

        /* Buffer for the decrypted text */
        unsigned char decryptedtext[128];

        int decryptedtext_len, ciphertext_len;

        /* Encrypt the plaintext */
        ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                                  ciphertext);

        /* Do something useful with the ciphertext here */
        printf("Ciphertext is:\n");
//        cout<<ciphertext<<endl;
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

        /* Decrypt the ciphertext */
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                    decryptedtext);

        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';
//
//        /* Show the decrypted text */
//        printf("Decrypted text is:\n");
//        printf("%s\n", decryptedtext);

        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
//        std::cout << "Client\n";
//        std::string sName(reinterpret_cast<char*>(plaintext));
//        std::cout <<sName<<endl;


        Sender sender = Sender(covert_channel_type);
        sender.send_message(message_to_send);

        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }
}
