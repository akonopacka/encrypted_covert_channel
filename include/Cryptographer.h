//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
#define ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H

#include <string>
using namespace std;
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <bits/stdc++.h>
#include "AES.h"
#include "../src/plusaes.hpp"

#include <string>
#include <vector>

class Cryptographer {
    string method = "aes";

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
/* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

public:
    Cryptographer(const string &method);
    void handleErrors();

    string encrypt(string plaintext);
    string decrypt(string ciphertext);

    string encrypt_aes_bin(string plaintext_);

    string decrypt_aes(string ciphertext_bin);


    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);
    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
            unsigned char *plaintext);
};


#endif //ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
