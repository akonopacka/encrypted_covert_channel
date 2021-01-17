#include <stdio.h>
#include <string>
#include <iostream>
#include "../src/des.hpp"
using namespace std;

const int MAXN = 1e7;
char message[MAXN];

int main(){
    freopen("ciphertext.in", "r", stdin);
    freopen("message.out", "w", stdout);
    char key[32] = {"0E329232EA6D0D73"}, mode[3] = {"De"};
    while(gets(message)) {
        cout << des(message, key, mode) << endl;
    }
    return 0;
}