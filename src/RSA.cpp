
#include "../include/RSA.h"

RSA *createRSAWithFilename(char *filename, int is_public) {
    FILE *fp = fopen(filename, "rb");

    if (fp == NULL) {
        printf("Unable to open file %s \n", filename);
        return NULL;
    }
    RSA *rsa = RSA_new();

    if (is_public) {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }
    return rsa;
}

string encrypt_rsa_(string plaintext_) {
    int padding = RSA_NO_PADDING;
    unsigned char encrypted[2048 / 8] = {};
    unsigned char *plaintext;
    char plainText[2048 / 8];
    strcpy((char *) plainText, plaintext_.c_str());
    const unsigned char *constStr = reinterpret_cast<const unsigned char *> (plaintext_.c_str());

    RSA *rsa = createRSAWithFilename("../keys/public.pem", 1);

    int encrypted_length = RSA_public_encrypt(plaintext_.length(), constStr, encrypted, rsa, padding);
    if (encrypted_length == -1) {
        char buf[128];
        cerr << "RSA_public_encrypt: " << ERR_error_string(ERR_get_error(), buf) << endl;
        exit(0);
    }
    string binary_string;
    string s = reinterpret_cast <char *>(encrypted);

    for (unsigned char &_char: encrypted) {
        binary_string += bitset<8>(_char).to_string();
    }
    return binary_string;
}

string decrypt_rsa_(string ciphertext_bin) {
    std::stringstream sstream(ciphertext_bin);
    std::string output;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        unsigned char c = (unsigned char) (bits.to_ulong());
        output += c;
    }
    const unsigned char *encrypted = reinterpret_cast<const unsigned char *> (output.c_str());
    int padding = RSA_NO_PADDING;
    unsigned char decrypted[2048 / 8] = {};
    RSA *rsa_decrypt = createRSAWithFilename("../keys/private.pem", 0);
    int decrypted_length = RSA_private_decrypt(2048 / 8, encrypted, decrypted, rsa_decrypt, padding);
    if (decrypted_length == -1) {
        char buf[128];
        cerr << "RSA_private_decrypt: " << ERR_error_string(ERR_get_error(), buf) << endl;
        return "";
    }
    string decrypted_part(reinterpret_cast<char *>(decrypted));
    return decrypted_part;
}