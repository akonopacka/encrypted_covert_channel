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
#include <stdexcept>
#include <iomanip>
#include <string>
#include <cstdint>

//#include "Present.h"
extern "C" {
// Get declaration for f(int i, char c, float x)
#include "../C_language/PRESENT.c"]
}
//#include "../include/openssl_rsa.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

#include <stdlib.h>
#include "../src/Clefia.hpp"


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
    string encrypt_present(string plaintext_);
    string decrypt_present(string ciphertext_bin);
    string encrypt_rsa(string plaintext_);
    string decrypt_rsa(string ciphertext_bin);
};


#endif //ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
