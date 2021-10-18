//
// Created by ak on 17.10.2021.
//


#include "../include/DES.h"

string DES::bit64_to_H(bs_64 x) {
    string str;
    int t = 63;
    for (int i = 0; i < 16; ++i) {
        int num = x[t] * 8 + x[t - 1] * 4 + x[t - 2] * 2 + x[t - 3];
        t -= 4;
        if (num < 10) {
            str += num + '0';
        } else {
            str += num + 'A' - 10;
        }
    }
    return str;
}

string DES::bit16_to_str(string str) {
    string ss;
    for (int i = 0; i < 16; i += 2) {
        int l, r;
        if (str[i] >= '0' && str[i] <= '9') l = str[i] - '0';
        else l = str[i] - 'A' + 10;
        if (str[i + 1] >= '0' && str[i + 1] <= '9') r = str[i + 1] - '0';
        else r = str[i + 1] - 'A' + 10;
        ss += (char) (l * 16 + r);
    }
    return ss;
}


bs_56 DES::getpc1(bs_64 k) {
    bs_56 bs56;
    for (int i = 55; i >= 0; --i) {
        bs56[i] = k[64 - PC_1[55 - i]];
    }
    return bs56;
}

bs_64 DES::_8char_to_bit64(char str[]) {
    bs_64 b;
    int num = 0;
    for (int i = 7; i >= 0; --i) {
        int x = str[i];
        do {
            b[num++] = x % 2;
            x /= 2;
        } while (num % 8 != 0);
    }

    return b;
}

bs_64 DES::H_to_bit64(char str[]) {
    bs_64 b;
    int num = 0, x;
    for (int i = 15; i >= 0; --i) {
        if (str[i] >= '0' && str[i] <= '9') {
            x = str[i] - '0';
        } else {
            x = str[i] - 'A' + 10;
        }
        do {
            b[num++] = x % 2;
            x /= 2;
        } while (num % 4 != 0);
    }

    return b;
}

bs_64 DES::_7check_to_bit64(char str[]) {
    bs_56 b;
    int num = 0;
    for (char i = 6; i >= 0; --i) {
        int x = str[i];
        do {
            b[num++] = x % 2;
            x /= 2;
        } while (num % 8 != 0);
    }
    num = 1;
    bs_64 x;
    int count = 0;
    for (int i = 0; i < 56; ++i) {
        x[i / 7 * 8 + i % 7 + 1] = b[i];
        if (b[i] == 1) count++;
        if ((i + 1) % 7 == 0) {
            x[((i + 1) / 7 - 1) * 8] = count % 2;
            count = 0;
        }
    }
    return x;
}

void DES::solvekey(char str[]) {
    int len = strlen(str);
    bs_64 k;
    if (len == 8) {
        k = _8char_to_bit64(str);
    } else if (len == 16) {
        k = H_to_bit64(str);
    } else {
        k = _7check_to_bit64(str);
    }

    bs_56 k_ = getpc1(k);
    bs_28 c[17], d[17];
    for (int i = 55; i >= 28; --i) {
        c[0][i - 28] = k_[i];
    }
    for (int i = 0; i < 28; ++i) {
        d[0][i] = k_[i];
    }

    for (int i = 1; i <= 16; ++i) {
        for (int j = 0; j < 28; ++j) {
            c[i][(j + move_table[i - 1]) % 28] = c[i - 1][j];
            d[i][(j + move_table[i - 1]) % 28] = d[i - 1][j];
        }
    }

    bs_56 cd[17];
    for (int i = 1; i <= 16; ++i) {
        for (int j = 0; j < 28; ++j) {
            cd[i][j] = d[i][j];
        }
        for (int jj = 0; jj < 28; ++jj) {
            cd[i][jj + 28] = c[i][jj];
        }
    }

    for (int i = 1; i <= 16; ++i) {
        for (int j = 47; j >= 0; --j) {
            kk[i][j] = cd[i][56 - PC_2[47 - j]];
        }
    }
}

bs_32 DES::f(bs_32 r, int time) {
    bs_48 er;
    for (int i = 47; i >= 0; --i) {
        er[i] = r[32 - E[47 - i]];
    }

    er ^= kk[time];
    bs_32 ff;
    int t = 0, co = 0;

    for (int i = 7; i >= 0; --i) {
        int row = er[t + 5] * 2 + er[t];
        int col = er[t + 4] * 8 + er[t + 3] * 4 + er[t + 2] * 2 + er[t + 1];
        int num = S_Box[i][row][col];
        do {
            ff[co++] = num % 2;
            num /= 2;
        } while (co % 4 != 0);
        t += 6;
    }

    bs_32 fff;
    for (int i = 31; i >= 0; --i) {
        fff[i] = ff[32 - P_Table[31 - i]];
    }

    return fff;
}


bs_64 DES::solveE(bs_64 x) {
    bs_64 ip;
    for (int i = 63; i >= 0; --i) {
        ip[i] = x[64 - IP_[63 - i]];
    }

    bs_32 l, r, tmp;
    for (int i = 0; i < 32; ++i) {
        r[i] = ip[i];
    }
    for (int i = 32; i < 64; ++i) {
        l[i - 32] = ip[i];
    }

    for (int i = 1; i <= 16; ++i) {
        tmp = r;
        r = l ^ f(r, i);
        l = tmp;
    }
    bs_64 R_16_L_16;
    for (int i = 0; i < 32; ++i) {
        R_16_L_16[i] = l[i];
    }
    for (int i = 0; i < 32; ++i) {
        R_16_L_16[i + 32] = r[i];
    }

    bs_64 en;
    for (int i = 63; i >= 0; --i) {
        en[i] = R_16_L_16[64 - IPR_Table[63 - i]];
    }

    return en;
}

bs_64 DES::solveD_(bs_64 x) {
    bs_64 ip;
    for (int i = 63; i >= 0; --i) {
        ip[i] = x[64 - IP_[63 - i]];
    }

    bs_32 l, r, tmp;
    for (int i = 0; i < 32; ++i) {
        l[i] = ip[i];
    }
    for (int i = 32; i < 64; ++i) {
        r[i - 32] = ip[i];
    }

    for (int i = 16; i >= 1; --i) {
        tmp = l;
        l = r ^ f(l, i);
        r = tmp;
    }
    bs_64 R_16_L_16;
    for (int i = 0; i < 32; ++i) {
        R_16_L_16[i] = r[i];
    }
    for (int i = 0; i < 32; ++i) {
        R_16_L_16[i + 32] = l[i];
    }

    bs_64 en;
    for (int i = 63; i >= 0; --i) {
        en[i] = R_16_L_16[64 - IPR_Table[63 - i]];
    }

    return en;
}

string DES::des(char me[], char ke[], char mo[]) {
    solvekey(ke);
    string ss;
    if (mo[0] == 'D') {
        int len = strlen(me);
        for (int i = 0; i < len; i += 16) {
            bs_64 m = H_to_bit64(me + i);
            bs_64 en = solveD_(m);
            string dcode = bit64_to_H(en);
            ss += bit16_to_str(dcode);
        }
    } else {
        int len = strlen(me);
        while (len % 8 != 0) {
            me[len++] = 0;
        }
        for (int i = 0; i < len; i += 8) {
            bs_64 m = _8char_to_bit64(me + i);
            bs_64 en = solveE(m);
            string encode = bit64_to_H(en);
            ss += encode;
        }
    }
    return ss;
}
