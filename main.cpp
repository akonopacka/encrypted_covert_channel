/*
	Better description
*/
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <tins/tins.h>
#include <chrono>
#include <thread>
#include <bitset>
#include <sstream>
#include <cstdlib>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
using std::string;

using namespace Tins;
using namespace std;


string message = "";
std::chrono::high_resolution_clock::time_point time_of_last_packet = std::chrono::high_resolution_clock::now();
std::chrono::high_resolution_clock::time_point time_received;
std::chrono::duration<double, std::milli> time_span;


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

bool callback_storage_CC(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if(ip.dst_addr()=="192.55.0.1"){
        std::cout << ip.src_addr() << ':' << tcp.sport() << " -> "
                  << ip.dst_addr() << ':' << tcp.dport() << "    "
                  << ip.tot_len() << endl;
        int a = ip.tot_len()-40;
        char c = static_cast<char>(a);

        message = message+c;
    }
    if (message[message.size()-1] == '0'){
        std::cout<<"Received message: "<<message<<endl;
        message = "";
    }
    return true;
}

bool callback_timing_CC(const PDU &pdu) {
    // Find the IP layer
    const IP &ip = pdu.rfind_pdu<IP>();
    // Find the TCP layer
    const TCP &tcp = pdu.rfind_pdu<TCP>();

    if(ip.dst_addr()=="192.55.0.1"){
        time_received = std::chrono::high_resolution_clock::now();
        time_span = time_received - time_of_last_packet;
        double interval = time_span.count();

//        std::cout <<endl<<endl<< ip.src_addr() << ':' << tcp.sport() << " -> "
//                  << ip.dst_addr() << ':' << tcp.dport() << "    "
//                  << ip.tot_len() << endl;
        std::cout << "Interval: " << interval<<endl;
        if (interval > 5000){
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
            }

            message = "";
        }
        else if(interval < 1){
            cout<< "0"<<endl;
            message = message + "0";
        }
        else{
            message = message + "1";

        }
//        std::cout<<"Received message: "<<message<<endl;
        time_of_last_packet = std::chrono::high_resolution_clock::now();
    }

    return true;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!strcmp(argv[1], "--server")) {
            std::cout << "Server!\n";
            Sniffer("wlo1").sniff_loop(callback_timing_CC);
        }
    }

    if (!strcmp(argv[1], "--client")) {


        /* A 256 bit key */
        unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";

        /* Message to be encrypted */
        unsigned char *plaintext =
                (unsigned char *)"The quick brown fox jumps over the lazy dog";

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
        cout<<ciphertext<<endl;
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

        /* Decrypt the ciphertext */
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                    decryptedtext);

        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);

        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        std::cout << "Client\n";
        string message = "HELLO1";
        string covert_channel_type = "timing";
        if (covert_channel_type!="timing"){
            for (std::string::size_type i = 0; i < message.size(); i++) {
                std::cout<<"Storage method"<<endl;
                char a = message[i];
                int ia = (int)a;
                std::cout << message[i] << ' '<<ia<<endl;
                PacketSender sender;
                std::string s(ia, 'a');
                IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU(s);
                sender.send(pkt);

                std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
                time_span = t2 - t1;
                double interval = time_span.count();
                cout<<"It should be 100: "<<interval<<endl;
            }
        }
        else{
            std::cout<<"Timing method"<<endl;
            string word = "OLA";
            string binaryString = "";
            for (char& _char : word) {
                binaryString +=bitset<8>(_char).to_string();
            }
            cout<<"word: "<<word<<" bin: "<<binaryString<<endl;
            message = binaryString;
            PacketSender sender;
            IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU("s");
            sender.send(pkt);
            for (std::string::size_type i = 0; i < message.size(); i++) {
                if (message[i]=='0'){
                    std::cout << message[i] << endl;
                    PacketSender sender;
                    IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU("s");
                    sender.send(pkt);
                }
                else{
                    std::cout << message[i] << endl;
                    PacketSender sender;
                    IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU("s");
                    sender.send(pkt);
                    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                }
            }
        }
        PacketSender sender;
        IP pkt = IP("192.55.0.1") / TCP(22) / RawPDU("s");
        sender.send(pkt);

        std::cout<<endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(8000));
        int ia = (int)'0';
        std::string s(ia, 'a');
        sender.send(pkt);

        std::cout << "Packet has been sent";

        // sleep for 1 seconds
        sleep(1);
        return 0;
    } else {
        std::cerr << "Bad usage";
        return 1;
    }

}
