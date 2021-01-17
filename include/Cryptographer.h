//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
#define ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H

#include <string>
#include <vector>

#include "../src/aes.hpp"
//#include "../clefia/clefia.h"
#include "../src/des.hpp"
#include <sstream>
#include <iostream>



using namespace std;

class Cryptographer {
    string method = "aes";

public:
    Cryptographer(const string &method);
    string encrypt(string plaintext);
    string decrypt(string ciphertext);
    string encrypt_aes(string plaintext_);
    string decrypt_aes(string ciphertext_bin);
    string encrypt_clefia(string plaintext_);
    string decrypt_clefia(string ciphertext_bin);
    string encrypt_des(string plaintext_);
    string decrypt_des(string ciphertext_bin);
};


#endif //ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
