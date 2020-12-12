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
#include "include/Sender.h"
//#include "include/Globals.h"
#include "include/Cryptographer.h"

unsigned int microseconds;

using namespace Tins;
using namespace std;

string message = "";
std::chrono::high_resolution_clock::time_point time_of_last_packet = std::chrono::high_resolution_clock::now();
std::chrono::high_resolution_clock::time_point time_received;
std::chrono::duration<double, std::milli> time_span;
double last_packet_timestamp = 0;
/* A 256 bit key */
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

/* A 128 bit IV */
unsigned char *iv = (unsigned char *)"0123456789012345";


string covert_channel_type = "storage";

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

bool storage_callback(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();

//    if(ip.dst_addr()=="192.55.0.1"){
    if(tcp.dport()==22){
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len()-40;
        char c = static_cast<char>(a);

        message = message+c;

        if (message[message.size()-1] == '0'){
            std::cout<<"Received message: "<<message<<endl;
            message = "";
        }
    }
    return true;
}

bool timing_callback(const PDU &pdu) {
    time_received = std::chrono::high_resolution_clock::now();
    time_span = time_received - time_of_last_packet;
    double interval = time_span.count();
//    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const UDP &udp = pdu.rfind_pdu<UDP>();
    std::cout << udp.sport()<< ' ';
    Tins::Packet packet = Tins::Packet(pdu);
    Timestamp ts = packet.timestamp();
    double timestamp = ts.seconds()*1000000 + ts.microseconds();
    std::cout<<std::fixed<<"Seconds: "<<ts.seconds()<<" microseconds:"<<ts.microseconds()<<endl;
    double inv = timestamp - last_packet_timestamp ;
    std::cout<<"Inter: "<< inv<<" "<< "Ts: " << timestamp << std::endl;

    //    std::cout <<endl<<endl<< ip.src_addr() << ':' << udp.sport() << " -> "
//          << ip.dst_addr() << ':' << udp.dport() << "    "
//          << ip.tot_len() << endl;
//
    if(udp.dport()==22){
//        time_span = time_received - time_of_last_packet;
//        double interval = time_span.count();
//        std::cout <<endl ip.src_addr() << ':' << udp.sport() << " -> "
//                  << ip.dst_addr() << ':' << udp.dport() << "    "
//                  << ip.tot_len() << endl;
//        std::cout << "Interval: " << interval<<" ";

        if(inv < 1000){
            message = message + "0";
            std::cout << "0"<<endl;
        }
        else if (inv < 4000000){
            message = message + "1";
            std::cout << "1"<<endl;
        }
        else {
            if(message!=""){
                message.erase (0,1);
                std::cout<<"Received message: "<<message<<endl;
                std::stringstream sstream(message);
                std::string output;
                while(sstream.good())
                {
                    std::bitset<8> bits;
                    sstream >> bits;
                    char c = char(bits.to_ulong());
                    output += c;
                }
                std::cout <<"Uncoded message: "<< output<<endl;
    //                unsigned char ciphertext[128];
    //                /* Buffer for the decrypted text */
    //                unsigned char decryptedtext[128];
    //                int decryptedtext_len, ciphertext_len;
    //                /* Decrypt the ciphertext */
    //
    //                std::copy( output.begin(), output.end(), ciphertext );
    //                ciphertext[output.length()] = 0;
    //                std::cout << ciphertext << std::endl;
    //                ciphertext_len = output.length()-1;
    //
    //                decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
    //                                            decryptedtext);
    //
    //                /* Add a NULL terminator. We are expecting printable text */
    //                decryptedtext[decryptedtext_len] = '\0';
    //
    //                /* Show the decrypted text */
    //                printf("Decrypted text is:\n");
    //                printf("%s\n", decryptedtext);
            }
            message = "";
        }
//        std::cout<<"Received message: "<<message<<endl;
        time_of_last_packet = std::chrono::high_resolution_clock::now();
        last_packet_timestamp = ts.seconds()*1000000 + ts.microseconds();
    }

    return true;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {

            if(covert_channel_type!="timing"){
                std::cout << "Server! - Storage method\n";
                Sniffer sniffer("lo");
                sniffer.set_filter("tcp&&port 22");
                Sniffer("lo").sniff_loop(storage_callback);
            }
            else{
                std::cout << "Server! - Timing method\n";
                SnifferConfiguration sniffer_configuration = SnifferConfiguration();
                sniffer_configuration.set_immediate_mode(false);
//                sniffer_configuration.set_timeout(1);
                Sniffer sniffer("lo", sniffer_configuration);
//                Receiver receiver = Receiver();
                sniffer.set_filter("udp&&port 22");
                sniffer.sniff_loop(timing_callback);
//                sniffer.sniff_loop(receiver.timing_callback);
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
        std::cout << "Client\n";
        std::string sName(reinterpret_cast<char*>(plaintext));
        std::cout <<sName<<endl;
//        string message = "HELLO1";
        string message = sName;


        if (covert_channel_type!="timing"){
//            for (std::string::size_type i = 0; i < message.size(); i++) {
//                std::cout<<"Storage method"<<endl;
//                char a = message[i];
//                int ia = (int)a;
//                std::cout << message[i] << ' '<<ia<<endl;
//                PacketSender sender;
//                std::string s(ia, 'a');
//                IP pkt = IP("127.0.0.1") / UDP(22) / RawPDU(s);
//                sender.send(pkt);
//
//                double interval = time_span.count();
//                cout<<"It should be 100: "<<interval<<endl;
//            }
//            PacketSender sender;
//            IP pkt = IP("127.0.0.1") / UDP(22) / RawPDU("s");
//            int ia = (int)'0';
//            std::string s(ia, 'a');
//            sender.send(pkt);
            Sender sender = Sender("Dluzsza proba","storage");
            sender.send_with_storage_method();
        }
        else{
            Sender sender = Sender("Dluzsza proba","timing");
            sender.send_with_timing_method();
        }
        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }

}
