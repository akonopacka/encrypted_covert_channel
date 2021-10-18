//
// Created by ak on 17.10.2021.
//

#ifndef ENCRYPTED_COVERT_CHANNEL_DES_H
#define ENCRYPTED_COVERT_CHANNEL_DES_H

#include <bitset>
#include "tables.h"
#include "string.h"
#include <iostream>

#define bs_24 bitset<24>
#define bs_28 bitset<28>
#define bs_32 bitset<32>
#define bs_48 bitset<48>
#define bs_64 bitset<64>
#define bs_56 bitset<56>
using namespace std;

class DES {
public:
    string bit64_to_H(bs_64 x);
    string bit16_to_str(string str);
    bs_56 getpc1(bs_64 k);
    bs_64 _8char_to_bit64(char str[]);
    bs_64 H_to_bit64(char str[]);
    bs_64 _7check_to_bit64(char str[]);
    void solvekey(char str[]);
    bs_32 f(bs_32 r, int time);
    bs_64 solveE(bs_64 x);
    bs_64 solveD_(bs_64 x);
    string des(char me[], char ke[], char mo[]);
    bs_48 kk[17];
};


#endif //ENCRYPTED_COVERT_CHANNEL_DES_H
