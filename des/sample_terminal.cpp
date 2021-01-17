#include <stdio.h>
#include <string>
#include <iostream>
#include "../src/des.hpp"
using namespace std;

const int MAXN = 1e5+10;
char message[MAXN], key[MAXN], mode[3];

int main(){
    printf("Please input message!\n");
    gets(message);
    do {
        printf("Please input correct key!(correct means 16 bit hexadecimalf or 8 bit any char or 7 bit any char)\n");
        gets(key);
    } while(strlen(key) != 8 && strlen(key) != 16 && strlen(key) != 7);
    printf("Plese input mode!(E for Encryption or D for Decrypt)\n");
    gets(mode);
    string solve = des(message, key, mode);
    cout << solve << endl;
    return 0;
}


/*
M = 0123456789ABCDEF
K = 133457799BBCDFF1
C = 6CBD22858BCEDB79ABA1A7BE2214C542

M = Your lips are smoother than vaseline
K = 0E329232EA6D0D73
C = C0999FDDE378D7ED727DA00BCA5A84EE47F269A4D6438190D9D52F78F5358499CF8700010F88469B

M = 8787878787878787
K = 0E329232EA6D0D73
C = 966D5E4DFACA272B966D5E4DFACA272B
*/