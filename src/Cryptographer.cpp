//
// Created by root on 02/11/2020.
//

#include "../include/Cryptographer.h"


Cryptographer::Cryptographer(const string &method) : method(method) {}

string Cryptographer::encrypt(string plaintext){
    if (method=="aes"){
        string s = encrypt_aes_bin(plaintext);
//        cout<<"encr:"<<s<<endl;
        return s;
    }
    return "OK";
}

string Cryptographer::decrypt(string ciphertext){
    if (method=="aes"){
        return decrypt_aes(ciphertext);
    }
    return "OK";
}

string Cryptographer::encrypt_aes_bin(string plaintext_) {

    const std::string raw_data = plaintext_;
    const std::vector<unsigned char> key_ = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
    const unsigned char iv_[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };

    // encrypt
    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    plusaes::encrypt_cbc((unsigned char*)raw_data.data(), raw_data.size(), &key_[0], key_.size(), &iv_, &encrypted[0], encrypted.size(), true);
    // fb 7b ae 95 d5 0f c5 6f 43 7d 14 6b 6a 29 15 70

    cout<<"Message: "<<plaintext_<<" Encrypted: "<<endl;

    for (int i= 0 ;i<  encrypted.size(); ++i) {
        cout << encrypted[i] ;
    }
    cout<<endl;
    string binaryString = "";

    for (int i= 0 ;i<  encrypted.size(); ++i) {
        binaryString +=bitset<8>(encrypted[i]).to_string();
    }
//    Checking decription
//    decrypt_aes(binaryString);
    return binaryString;
}

string Cryptographer::decrypt_aes(string ciphertext_bin) {

    const std::vector<unsigned char> key_1 = plusaes::key_from_string(&"EncryptionKey128"); // 16-char = 128-bit
    const unsigned char iv_1[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    };
    const unsigned long encrypted_size = 32;
//            plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    // decrypt
    unsigned long padded_size = 0;
    std::vector<unsigned char> decrypted(encrypted_size);

    std::stringstream sstream(ciphertext_bin);
    int i = 0;
    while (sstream.good()) {
        std::bitset<8> bits;
        sstream >> bits;
        unsigned char c;
        c = bits.to_ulong();
        encrypted[i] = c;
        i++;
    }

    plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key_1[0], key_1.size(), &iv_1, &decrypted[0], decrypted.size(), &padded_size);
    // Hello, plusaes

    string s(decrypted.begin(), decrypted.end());
    return s;
}
