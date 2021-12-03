#ifndef RSA_H
#define RSA_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <iostream>
#include <cstring>
#include <bitset>
#include <sstream>

using namespace std;


//    char *public_key_path = "../keys/public.pem";
//    char *private_key_path = "../keys/private.pem";

RSA *createRSAWithFilename(char *filename, int is_public);

string encrypt_rsa_(string plaintext_);

string decrypt_rsa_(string ciphertext_bin);

#endif //RSA_H