//
// Created by root on 02/11/2020.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
#define ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H

#include <string>
#include <vector>
#include <bits/stdc++.h>
#include "../src/aes.hpp"


using namespace std;

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

};


#endif //ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
