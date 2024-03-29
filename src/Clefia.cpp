#include "../include/Clefia.h"

void Clefia::ByteCpy(unsigned char *dst, const unsigned char *src, int bytelen) {
    while (bytelen-- > 0) {
        *dst++ = *src++;
    }
}

void Clefia::ByteXor(unsigned char *dst, const unsigned char *a, const unsigned char *b, int bytelen) {
    while (bytelen-- > 0) {
        *dst++ = *a++ ^ *b++;
    }
}

unsigned char Clefia::ClefiaMul2(unsigned char x) {
    /* multiplication over GF(2^8) (p(x) = '11d') */
    if (x & 0x80U) {
        x ^= 0x0eU;
    }
    return ((x << 1) | (x >> 7));
}

void Clefia::ClefiaF0Xor(unsigned char *dst, const unsigned char *src, const unsigned char *rk) {
    unsigned char x[4], y[4], z[4];

    /* F0 */
    /* Key addition */
    ByteXor(x, src, rk, 4);
    /* Substitution layer */
    z[0] = clefia_s0[x[0]];
    z[1] = clefia_s1[x[1]];
    z[2] = clefia_s0[x[2]];
    z[3] = clefia_s1[x[3]];
    /* Diffusion layer (M0) */
    y[0] = z[0] ^ ClefiaMul2(z[1]) ^ ClefiaMul4(z[2]) ^ ClefiaMul6(z[3]);
    y[1] = ClefiaMul2(z[0]) ^ z[1] ^ ClefiaMul6(z[2]) ^ ClefiaMul4(z[3]);
    y[2] = ClefiaMul4(z[0]) ^ ClefiaMul6(z[1]) ^ z[2] ^ ClefiaMul2(z[3]);
    y[3] = ClefiaMul6(z[0]) ^ ClefiaMul4(z[1]) ^ ClefiaMul2(z[2]) ^ z[3];

    /* Xoring after F0 */
    ByteCpy(dst + 0, src + 0, 4);
    ByteXor(dst + 4, src + 4, y, 4);
}

void Clefia::ClefiaF1Xor(unsigned char *dst, const unsigned char *src, const unsigned char *rk) {
    unsigned char x[4], y[4], z[4];

    /* F1 */
    /* Key addition */
    ByteXor(x, src, rk, 4);
    /* Substitution layer */
    z[0] = clefia_s1[x[0]];
    z[1] = clefia_s0[x[1]];
    z[2] = clefia_s1[x[2]];
    z[3] = clefia_s0[x[3]];
    /* Diffusion layer (M1) */
    y[0] = z[0] ^ ClefiaMul8(z[1]) ^ ClefiaMul2(z[2]) ^ ClefiaMulA(z[3]);
    y[1] = ClefiaMul8(z[0]) ^ z[1] ^ ClefiaMulA(z[2]) ^ ClefiaMul2(z[3]);
    y[2] = ClefiaMul2(z[0]) ^ ClefiaMulA(z[1]) ^ z[2] ^ ClefiaMul8(z[3]);
    y[3] = ClefiaMulA(z[0]) ^ ClefiaMul2(z[1]) ^ ClefiaMul8(z[2]) ^ z[3];

    /* Xoring after F1 */
    ByteCpy(dst + 0, src + 0, 4);
    ByteXor(dst + 4, src + 4, y, 4);
}

void Clefia::ClefiaGfn4(unsigned char *y, const unsigned char *x, const unsigned char *rk, int r) {
    unsigned char fin[16], fout[16];

    ByteCpy(fin, x, 16);
    while (r-- > 0) {
        ClefiaF0Xor(fout + 0, fin + 0, rk + 0);
        ClefiaF1Xor(fout + 8, fin + 8, rk + 4);
        rk += 8;
        if (r) { /* swapping for encryption */
            ByteCpy(fin + 0, fout + 4, 12);
            ByteCpy(fin + 12, fout + 0, 4);
        }
    }
    ByteCpy(y, fout, 16);
}

void Clefia::ClefiaGfn8(unsigned char *y, const unsigned char *x, const unsigned char *rk, int r) {
    unsigned char fin[32], fout[32];

    ByteCpy(fin, x, 32);
    while (r-- > 0) {
        ClefiaF0Xor(fout + 0, fin + 0, rk + 0);
        ClefiaF1Xor(fout + 8, fin + 8, rk + 4);
        ClefiaF0Xor(fout + 16, fin + 16, rk + 8);
        ClefiaF1Xor(fout + 24, fin + 24, rk + 12);
        rk += 16;
        if (r) { /* swapping for encryption */
            ByteCpy(fin + 0, fout + 4, 28);
            ByteCpy(fin + 28, fout + 0, 4);
        }
    }
    ByteCpy(y, fout, 32);
}

void Clefia::ClefiaGfn4Inv(unsigned char *y, const unsigned char *x, const unsigned char *rk, int r) {
    unsigned char fin[16], fout[16];

    rk += (r - 1) * 8;
    ByteCpy(fin, x, 16);
    while (r-- > 0) {
        ClefiaF0Xor(fout + 0, fin + 0, rk + 0);
        ClefiaF1Xor(fout + 8, fin + 8, rk + 4);
        rk -= 8;
        if (r) { /* swapping for decryption */
            ByteCpy(fin + 0, fout + 12, 4);
            ByteCpy(fin + 4, fout + 0, 12);
        }
    }
    ByteCpy(y, fout, 16);
}

void Clefia::ClefiaDoubleSwap(unsigned char *lk) {
    unsigned char t[16];

    t[0] = (lk[0] << 7) | (lk[1] >> 1);
    t[1] = (lk[1] << 7) | (lk[2] >> 1);
    t[2] = (lk[2] << 7) | (lk[3] >> 1);
    t[3] = (lk[3] << 7) | (lk[4] >> 1);
    t[4] = (lk[4] << 7) | (lk[5] >> 1);
    t[5] = (lk[5] << 7) | (lk[6] >> 1);
    t[6] = (lk[6] << 7) | (lk[7] >> 1);
    t[7] = (lk[7] << 7) | (lk[15] & 0x7fU);

    t[8] = (lk[8] >> 7) | (lk[0] & 0xfeU);
    t[9] = (lk[9] >> 7) | (lk[8] << 1);
    t[10] = (lk[10] >> 7) | (lk[9] << 1);
    t[11] = (lk[11] >> 7) | (lk[10] << 1);
    t[12] = (lk[12] >> 7) | (lk[11] << 1);
    t[13] = (lk[13] >> 7) | (lk[12] << 1);
    t[14] = (lk[14] >> 7) | (lk[13] << 1);
    t[15] = (lk[15] >> 7) | (lk[14] << 1);

    ByteCpy(lk, t, 16);
}

void Clefia::ClefiaConSet(unsigned char *con, const unsigned char *iv, int lk) {
    unsigned char t[2];
    unsigned char tmp;

    ByteCpy(t, iv, 2);
    while (lk-- > 0) {
        con[0] = t[0] ^ 0xb7U; /* P_16 = 0xb7e1 (natural logarithm) */
        con[1] = t[1] ^ 0xe1U;
        con[2] = ~((t[0] << 1) | (t[1] >> 7));
        con[3] = ~((t[1] << 1) | (t[0] >> 7));
        con[4] = ~t[0] ^ 0x24U; /* Q_16 = 0x243f (circle ratio) */
        con[5] = ~t[1] ^ 0x3fU;
        con[6] = t[1];
        con[7] = t[0];
        con += 8;

        /* updating T */
        if (t[1] & 0x01U) {
            t[0] ^= 0xa8U;
            t[1] ^= 0x30U;
        }
        tmp = t[0] << 7;
        t[0] = (t[0] >> 1) | (t[1] << 7);
        t[1] = (t[1] >> 1) | tmp;
    }
}

void Clefia::ClefiaKeySet128(unsigned char *rk, const unsigned char *skey) {
    const unsigned char iv[2] = {0x42U, 0x8aU}; /* cubic root of 2 */
    unsigned char lk[16];
    unsigned char con128[4 * 60];
    int i;

    /* generating CONi^(128) (0 <= i < 60, lk = 30) */
    ClefiaConSet(con128, iv, 30);
    /* GFN_{4,12} (generating L from K) */
    ClefiaGfn4(lk, skey, con128, 12);

    ByteCpy(rk, skey, 8); /* initial whitening key (WK0, WK1) */
    rk += 8;
    for (i = 0; i < 9; i++) { /* round key (RKi (0 <= i < 36)) */
        ByteXor(rk, lk, con128 + i * 16 + (4 * 24), 16);
        if (i % 2) {
            ByteXor(rk, rk, skey, 16); /* Xoring K */
        }
        ClefiaDoubleSwap(lk); /* Updating L (DoubleSwap function) */
        rk += 16;
    }
    ByteCpy(rk, skey + 8, 8); /* final whitening key (WK2, WK3) */
}

void Clefia::ClefiaKeySet192(unsigned char *rk, const unsigned char *skey) {
    const unsigned char iv[2] = {0x71U, 0x37U}; /* cubic root of 3 */
    unsigned char skey256[32];
    unsigned char lk[32];
    unsigned char con192[4 * 84];
    int i;

    ByteCpy(skey256, skey, 24);
    for (i = 0; i < 8; i++) {
        skey256[i + 24] = ~skey[i];
    }

    /* generating CONi^(192) (0 <= i < 84, lk = 42) */
    ClefiaConSet(con192, iv, 42);
    /* GFN_{8,10} (generating L from K) */
    ClefiaGfn8(lk, skey256, con192, 10);

    ByteXor(rk, skey256, skey256 + 16, 8); /* initial whitening key (WK0, WK1) */
    rk += 8;
    for (i = 0; i < 11; i++) { /* round key (RKi (0 <= i < 44)) */
        if ((i / 2) % 2) {
            ByteXor(rk, lk + 16, con192 + i * 16 + (4 * 40), 16); /* LR */
            if (i % 2) {
                ByteXor(rk, rk, skey256 + 0, 16); /* Xoring KL */
            }
            ClefiaDoubleSwap(lk + 16); /* updating LR */
        } else {
            ByteXor(rk, lk + 0, con192 + i * 16 + (4 * 40), 16); /* LL */
            if (i % 2) {
                ByteXor(rk, rk, skey256 + 16, 16); /* Xoring KR */
            }
            ClefiaDoubleSwap(lk + 0);  /* updating LL */
        }
        rk += 16;
    }
    ByteXor(rk, skey256 + 8, skey256 + 24, 8); /* final whitening key (WK2, WK3) */
}

void Clefia::ClefiaKeySet256(unsigned char *rk, const unsigned char *skey) {
    const unsigned char iv[2] = {0xb5, 0xc0U}; /* cubic root of 5 */
    unsigned char lk[32];
    unsigned char con256[4 * 92];
    int i;

    /* generating CONi^(256) (0 <= i < 92, lk = 46) */
    ClefiaConSet(con256, iv, 46);
    /* GFN_{8,10} (generating L from K) */
    ClefiaGfn8(lk, skey, con256, 10);

    ByteXor(rk, skey, skey + 16, 8); /* initial whitening key (WK0, WK1) */
    rk += 8;
    for (i = 0; i < 13; i++) { /* round key (RKi (0 <= i < 52)) */
        if ((i / 2) % 2) {
            ByteXor(rk, lk + 16, con256 + i * 16 + (4 * 40), 16); /* LR */
            if (i % 2) {
                ByteXor(rk, rk, skey + 0, 16); /* Xoring KL */
            }
            ClefiaDoubleSwap(lk + 16); /* updating LR */
        } else {
            ByteXor(rk, lk + 0, con256 + i * 16 + (4 * 40), 16); /* LL */
            if (i % 2) {
                ByteXor(rk, rk, skey + 16, 16); /* Xoring KR */
            }
            ClefiaDoubleSwap(lk + 0);  /* updating LL */
        }
        rk += 16;
    }
    ByteXor(rk, skey + 8, skey + 24, 8); /* final whitening key (WK2, WK3) */
}


int Clefia::ClefiaKeySet(unsigned char *rk, const unsigned char *skey, const int key_bitlen) {
    if (128 == key_bitlen) {
        ClefiaKeySet128(rk, skey);
        return 18;
    } else if (192 == key_bitlen) {
        ClefiaKeySet192(rk, skey);
        return 22;
    } else if (256 == key_bitlen) {
        ClefiaKeySet256(rk, skey);
        return 26;
    }

    return 0; /* invalid key_bitlen */
}

void Clefia::ClefiaEncrypt(unsigned char *ct, const unsigned char *pt, const unsigned char *rk, const int r) {
    unsigned char rin[16], rout[16];

    ByteCpy(rin, pt, 16);

    ByteXor(rin + 4, rin + 4, rk + 0, 4); /* initial key whitening */
    ByteXor(rin + 12, rin + 12, rk + 4, 4);
    rk += 8;

    ClefiaGfn4(rout, rin, rk, r); /* GFN_{4,r} */

    ByteCpy(ct, rout, 16);
    ByteXor(ct + 4, ct + 4, rk + r * 8 + 0, 4); /* final key whitening */
    ByteXor(ct + 12, ct + 12, rk + r * 8 + 4, 4);
}

void Clefia::ClefiaDecrypt(unsigned char *pt, const unsigned char *ct, const unsigned char *rk, const int r) {
    unsigned char rin[16], rout[16];

    ByteCpy(rin, ct, 16);

    ByteXor(rin + 4, rin + 4, rk + r * 8 + 8, 4); /* initial key whitening */
    ByteXor(rin + 12, rin + 12, rk + r * 8 + 12, 4);
    rk += 8;

    ClefiaGfn4Inv(rout, rin, rk, r); /* GFN^{-1}_{4,r} */

    ByteCpy(pt, rout, 16);
    ByteXor(pt + 4, pt + 4, rk - 8, 4); /* final key whitening */
    ByteXor(pt + 12, pt + 12, rk - 4, 4);
}

