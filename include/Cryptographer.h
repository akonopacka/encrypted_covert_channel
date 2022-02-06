#ifndef ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
#define ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H

#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <unistd.h>
#include <chrono>

#include "../src/AES.hpp"
#include "../src/Grain.c"
#include "../include/RSA.h"
#include "../include/DES.h"
#include "../include/Clefia.h"
#include "../include/Evaluation.h"

extern "C" {
// Get declaration for f(int i, char c, float x)
#include "../src/Present.c"

}

using namespace std;

class Cryptographer {
    string method = "aes";

public:
    Cryptographer(const string &method);

    string encrypt(string plaintext);

    string decrypt(string ciphertext);

    string encrypt_aes(string plaintext_);

    string decrypt_aes(string ciphertext_bin);

    string encrypt_aes_(string plaintext_);

    string decrypt_aes_(string ciphertext_bin);

    string encrypt_clefia(string plaintext_);

    string decrypt_clefia(string ciphertext_bin);

    string encrypt_clefia_(string plaintext_);

    string decrypt_clefia_(string ciphertext_bin);

    string encrypt_des(string plaintext_);

    string decrypt_des(string ciphertext_bin);

    string encrypt_present(string plaintext_);

    string decrypt_present(string ciphertext_bin);

    string encrypt_present_(string plaintext_);

    string decrypt_present_(string ciphertext_bin);

    string encrypt_rsa(string plaintext_);

    string decrypt_rsa(string ciphertext_bin);

    string encrypt_grain(string plaintext_);

    string decrypt_grain(string ciphertext_bin);

    string encrypt_grain_(string plaintext_);

    string decrypt_grain_(string ciphertext_bin);
};


#endif //ENCRYPTED_COVERT_CHANNEL_CRYPTOGRAPHER_H
